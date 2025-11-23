"""
Well-Known SIDs Base Class
Enthält alle bekannten Windows Well-Known SIDs
"""

class WellKnownSIDs:
    """Basisklasse mit Well-Known SIDs für Reader und Resolver"""
    
    def __init__(self, additional_well_known_sids=None):
        """
        Initialisiert die Well-Known SIDs
        
        Args:
            additional_well_known_sids: Optionales Dictionary mit zusätzlichen well-known SIDs
        """
        # Well-known SIDs
        self.well_known_sids = {
            # Universal Well-Known SIDs
            'S-1-0-0': 'NULL',
            'S-1-1-0': 'Everyone',
            'S-1-2-0': 'LOCAL',
            'S-1-2-1': 'CONSOLE LOGON',
            'S-1-3-0': 'CREATOR OWNER',
            'S-1-3-1': 'CREATOR GROUP',
            'S-1-3-2': 'CREATOR OWNER SERVER',
            'S-1-3-3': 'CREATOR GROUP SERVER',
            'S-1-3-4': 'OWNER RIGHTS',
            
            # NT AUTHORITY
            'S-1-5-1': 'NT AUTHORITY\\DIALUP',
            'S-1-5-2': 'NT AUTHORITY\\NETWORK',
            'S-1-5-3': 'NT AUTHORITY\\BATCH',
            'S-1-5-4': 'NT AUTHORITY\\INTERACTIVE',
            'S-1-5-6': 'NT AUTHORITY\\SERVICE',
            'S-1-5-7': 'NT AUTHORITY\\ANONYMOUS LOGON',
            'S-1-5-8': 'NT AUTHORITY\\PROXY',
            'S-1-5-9': 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS',
            'S-1-5-10': 'NT AUTHORITY\\SELF',
            'S-1-5-11': 'NT AUTHORITY\\Authenticated Users',
            'S-1-5-12': 'NT AUTHORITY\\RESTRICTED',
            'S-1-5-13': 'NT AUTHORITY\\TERMINAL SERVER USER',
            'S-1-5-14': 'NT AUTHORITY\\REMOTE INTERACTIVE LOGON',
            'S-1-5-15': 'NT AUTHORITY\\This Organization',
            'S-1-5-17': 'NT AUTHORITY\\IUSR',
            'S-1-5-18': 'NT AUTHORITY\\SYSTEM',
            'S-1-5-19': 'NT AUTHORITY\\LOCAL SERVICE',
            'S-1-5-20': 'NT AUTHORITY\\NETWORK SERVICE',
            
            # BUILTIN Groups
            'S-1-5-32-544': 'BUILTIN\\Administrators',
            'S-1-5-32-545': 'BUILTIN\\Users',
            'S-1-5-32-546': 'BUILTIN\\Guests',
            'S-1-5-32-547': 'BUILTIN\\Power Users',
            'S-1-5-32-548': 'BUILTIN\\Account Operators',
            'S-1-5-32-549': 'BUILTIN\\Server Operators',
            'S-1-5-32-550': 'BUILTIN\\Print Operators',
            'S-1-5-32-551': 'BUILTIN\\Backup Operators',
            'S-1-5-32-552': 'BUILTIN\\Replicators',
            'S-1-5-32-554': 'BUILTIN\\Pre-Windows 2000 Compatible Access',
            'S-1-5-32-555': 'BUILTIN\\Remote Desktop Users',
            'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
            'S-1-5-32-557': 'BUILTIN\\Incoming Forest Trust Builders',
            'S-1-5-32-558': 'BUILTIN\\Performance Monitor Users',
            'S-1-5-32-559': 'BUILTIN\\Performance Log Users',
            'S-1-5-32-560': 'BUILTIN\\Windows Authorization Access Group',
            'S-1-5-32-561': 'BUILTIN\\Terminal Server License Servers',
            'S-1-5-32-562': 'BUILTIN\\Distributed COM Users',
            'S-1-5-32-568': 'BUILTIN\\IIS_IUSRS',
            'S-1-5-32-569': 'BUILTIN\\Cryptographic Operators',
            'S-1-5-32-573': 'BUILTIN\\Event Log Readers',
            'S-1-5-32-574': 'BUILTIN\\Certificate Service DCOM Access',
            'S-1-5-32-575': 'BUILTIN\\RDS Remote Access Servers',
            'S-1-5-32-576': 'BUILTIN\\RDS Endpoint Servers',
            'S-1-5-32-577': 'BUILTIN\\RDS Management Servers',
            'S-1-5-32-578': 'BUILTIN\\Hyper-V Administrators',
            'S-1-5-32-579': 'BUILTIN\\Access Control Assistance Operators',
            'S-1-5-32-580': 'BUILTIN\\Remote Management Users',
            'S-1-5-32-582': 'BUILTIN\\Storage Replica Administrators',
        }
        
        # Zusätzliche well-known SIDs hinzufügen
        if additional_well_known_sids:
            self.well_known_sids.update(additional_well_known_sids)
    
    def is_well_known_sid(self, sid):
        """
        Prüft, ob eine SID eine well-known SID ist
        
        Args:
            sid: SID als String
            
        Returns:
            True wenn well-known, False sonst
        """
        return sid in self.well_known_sids
    
    def filter_well_known_from_dacl(self, dacl):
        """
        Filtert well-known SIDs aus einer DACL
        
        Args:
            dacl: Liste von ACE Dictionaries
            
        Returns:
            Gefilterte DACL ohne well-known SIDs
        """
        return [ace for ace in dacl if not self.is_well_known_sid(ace.get('sid', ''))]
    
    def filter_well_known_from_security_info(self, security_info):
        """
        Filtert well-known SIDs aus einem Security-Info Dictionary
        
        Args:
            security_info: Security-Info Dictionary
            
        Returns:
            Gefiltertes Security-Info Dictionary
        """
        result = security_info.copy()
        
        # DACL filtern
        if result.get('dacl'):
            result['dacl'] = self.filter_well_known_from_dacl(result['dacl'])
        
        # SACL filtern
        if result.get('sacl'):
            result['sacl'] = [ace for ace in result['sacl'] 
                            if not self.is_well_known_sid(ace.get('sid', ''))]
        
        return result
