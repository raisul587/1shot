"""Router-specific attack profiles and configurations."""

ROUTER_PROFILES = {
    # TP-Link Profiles
    'TP-LINK': {
        'default_delay': 0.5,
        'retry_attempts': 3,
        'timeout': 15,
        'pin_algorithms': ['pin24', 'pin28', 'pinBrcm1'],
        'models': {
            'WR841N': {
                'delay': 1.0,
                'timeout': 20,
                'pin_algorithms': ['pin28', 'pinBrcm1'],
                'versions': {
                    '13.0': {'delay': 1.5},
                    '14.0': {'delay': 2.0}
                }
            },
            'WR850N': {
                'delay': 0.8,
                'timeout': 18,
                'pin_algorithms': ['pin24', 'pinBrcm2']
            }
        }
    },
    # D-Link Profiles
    'D-LINK': {
        'default_delay': 0.8,
        'retry_attempts': 2,
        'timeout': 12,
        'pin_algorithms': ['pinDLink', 'pinDLink1'],
        'models': {
            'DIR-615': {
                'delay': 1.2,
                'timeout': 15,
                'pin_algorithms': ['pinDLink1']
            }
        }
    },
    # ASUS Profiles
    'ASUS': {
        'default_delay': 0.3,
        'retry_attempts': 4,
        'timeout': 10,
        'pin_algorithms': ['pinASUS', 'pin28'],
        'models': {
            'RT-N12': {
                'delay': 0.5,
                'timeout': 12,
                'pin_algorithms': ['pinASUS']
            }
        }
    },
    # Netgear Profiles
    'NETGEAR': {
        'default_delay': 1.0,
        'retry_attempts': 3,
        'timeout': 15,
        'pin_algorithms': ['pin24', 'pinBrcm3'],
        'models': {
            'WNR2000': {
                'delay': 1.5,
                'timeout': 18,
                'pin_algorithms': ['pin24']
            }
        }
    }
}

def get_router_profile(manufacturer, model=None, version=None):
    """Get router-specific attack profile."""
    if manufacturer not in ROUTER_PROFILES:
        return None
    
    profile = ROUTER_PROFILES[manufacturer].copy()
    
    if model and model in profile['models']:
        model_profile = profile['models'][model]
        profile.update(model_profile)
        
        if version and 'versions' in model_profile and version in model_profile['versions']:
            profile.update(model_profile['versions'][version])
    
    return profile

def get_pin_algorithms(manufacturer, model=None):
    """Get recommended PIN algorithms for a specific router."""
    profile = get_router_profile(manufacturer, model)
    return profile['pin_algorithms'] if profile else []

def get_timing_config(manufacturer, model=None, version=None):
    """Get timing configuration for a specific router."""
    profile = get_router_profile(manufacturer, model, version)
    if not profile:
        return {'delay': 1.0, 'timeout': 15, 'retry_attempts': 3}
    
    return {
        'delay': profile.get('delay', profile.get('default_delay', 1.0)),
        'timeout': profile.get('timeout', 15),
        'retry_attempts': profile.get('retry_attempts', 3)
    }
