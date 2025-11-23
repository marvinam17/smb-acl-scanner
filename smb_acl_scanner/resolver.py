from ldap3 import Connection, Server, ALL, NTLM

class LDAPResolver:
    """Klasse zur Auflösung von SIDs über LDAP"""
    
    def __init__(self, ldap_server, ldap_user, ldap_password, domain, further_well_known_sids={}):
        """
        Initialisiert den LDAP Resolver
        
        Args:
            ldap_server: LDAP Server Adresse
            ldap_user: LDAP Benutzername
            ldap_password: LDAP Passwort
            domain: Domain (z.B. 'example.com')
            further_well_known_sids: Zusätzliche well-known SIDs als Dictionary
        """
        self.ldap_server = ldap_server
        self.ldap_user = ldap_user
        self.ldap_password = ldap_password
        self.domain = domain
        self.connection = None
        self.sid_cache = {}
        
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
        self.well_known_sids.update(further_well_known_sids)
    
    def connect(self):
        """Verbindung zum LDAP-Server herstellen"""
        server = Server(self.ldap_server, get_info=ALL)
        
        # NTLM-Authentifizierung verwenden
        self.connection = Connection(
            server,
            user=self.ldap_user,
            password=self.ldap_password,
            authentication=NTLM,
            auto_bind=True
        )
    
    def disconnect(self):
        """LDAP-Verbindung trennen"""
        if self.connection:
            self.connection.unbind()
    
    def resolve_sid(self, sid, skip_well_known=False):
        """
        Löst eine SID zu einem lesbaren Namen auf
        
        Args:
            sid: SID als String (z.B. "S-1-5-21-...")
            skip_well_known: Wenn True, werden well-known SIDs nicht aufgelöst und die SID wird zurückgegeben
            
        Returns:
            Name des Benutzers/der Gruppe oder die SID, falls nicht gefunden
        """
        # Cache prüfen
        if sid in self.sid_cache:
            cached_value = self.sid_cache[sid]
            # Wenn skip_well_known aktiv ist und der gecachte Wert eine well-known SID ist, SID zurückgeben
            if skip_well_known and sid in self.well_known_sids:
                return sid
            return cached_value
        
        # Well-known SIDs
        if sid in self.well_known_sids:
            if skip_well_known:
                # Well-known SIDs überspringen und SID zurückgeben
                return sid
            else:
                self.sid_cache[sid] = self.well_known_sids[sid]
                return self.well_known_sids[sid]
        
        # LDAP-Abfrage
        try:
            # Base DN aus Domain konstruieren
            base_dn = ','.join([f'DC={part}' for part in self.domain.split('.')])
            
            # SID in Hex-Format konvertieren für LDAP-Abfrage
            # Nach objectSid suchen
            search_filter = f'(objectSid={sid})'
            
            self.connection.search(
                base_dn,
                search_filter,
                attributes=['sAMAccountName', 'name', 'distinguishedName', 'objectClass']
            )
            
            if self.connection.entries:
                entry = self.connection.entries[0]
                
                # Name extrahieren
                if hasattr(entry, 'sAMAccountName') and entry.sAMAccountName.value:
                    name = entry.sAMAccountName.value
                elif hasattr(entry, 'name') and entry.name.value:
                    name = entry.name.value
                else:
                    return sid
                
                # Nur den Namen zurückgeben, ohne Domain-Präfix
                self.sid_cache[sid] = name
                return name
            else:
                # Nicht gefunden, SID zurückgeben
                self.sid_cache[sid] = sid
                return sid
                
        except Exception as e:
            print(f"LDAP-Abfrage fehlgeschlagen für {sid}: {e}")
            self.sid_cache[sid] = sid
            return sid
    
    def resolve_multiple_sids(self, sids, skip_well_known=False):
        """
        Löst mehrere SIDs gleichzeitig auf (Performance-Optimierung)
        
        Args:
            sids: Liste von SIDs
            skip_well_known: Wenn True, werden well-known SIDs nicht aufgelöst
            
        Returns:
            Dictionary mit SID -> Name Mapping
        """
        result = {}
        unknown_sids = []
        
        # Zuerst Cache und Well-known SIDs prüfen
        for sid in sids:
            if sid in self.sid_cache:
                # Wenn skip_well_known aktiv ist und es eine well-known SID ist, SID verwenden
                if skip_well_known and sid in self.well_known_sids:
                    result[sid] = sid
                else:
                    result[sid] = self.sid_cache[sid]
            elif sid in self.well_known_sids:
                if skip_well_known:
                    # Well-known SID überspringen
                    result[sid] = sid
                else:
                    result[sid] = self.well_known_sids[sid]
                    self.sid_cache[sid] = self.well_known_sids[sid]
            else:
                unknown_sids.append(sid)
        
        # Unbekannte SIDs einzeln auflösen
        for sid in unknown_sids:
            result[sid] = self.resolve_sid(sid, skip_well_known=skip_well_known)
        
        return result
    
    def translate_acl_scan_results(self, scan_results, skip_well_known=False):
        """
        Übersetzt alle SIDs in ACL-Scan-Ergebnissen zu lesbaren Namen
        
        Args:
            scan_results: Liste oder Generator von Dictionaries aus scan_directory oder scan_acl_changes
            skip_well_known: Wenn True, werden well-known SIDs nicht übersetzt
            
        Returns:
            Generator von Dictionaries mit übersetzten SIDs
            
        Beispiel:
            reader = SMBACLReader("user", "pass", "DOMAIN")
            resolver = LDAPResolver("ldap.example.com", "user", "pass", "example.com")
            resolver.connect()
            
            scan_results = reader.scan_acl_changes("\\\\server\\share")
            translated = resolver.translate_acl_scan_results(scan_results)
            
            for item in translated:
                print(f"{item['path']}")
                for ace in item['security']['dacl']:
                    print(f"  {ace['sid_name']}: {ace['permissions']}")
        """
        for item in scan_results:
            # Wenn ein Fehler aufgetreten ist, einfach weitergeben
            if 'error' in item:
                yield item
                continue
            
            # Security-Info übersetzen
            if 'security' in item and item['security']:
                item['security'] = self.translate_security_info(
                    item['security'], 
                    skip_well_known=skip_well_known
                )
            
            yield item
    
    def translate_security_info(self, security_info, skip_well_known=False):
        """
        Übersetzt alle SIDs in einem Security-Info Dictionary zu lesbaren Namen
        
        Args:
            security_info: Security-Info Dictionary aus parse_security_descriptor
            skip_well_known: Wenn True, werden well-known SIDs nicht übersetzt
            
        Returns:
            Security-Info Dictionary mit zusätzlichen '*_name' Feldern für übersetzte SIDs
        """
        # Kopie erstellen, um Original nicht zu verändern
        result = security_info.copy()
        
        # Owner übersetzen
        if result.get('owner'):
            result['owner_name'] = self.resolve_sid(result['owner'], skip_well_known=skip_well_known)
        
        # Group übersetzen
        if result.get('group'):
            result['group_name'] = self.resolve_sid(result['group'], skip_well_known=skip_well_known)
        
        # DACL übersetzen
        if result.get('dacl'):
            translated_dacl = []
            for ace in result['dacl']:
                ace_copy = ace.copy()
                if 'sid' in ace_copy:
                    ace_copy['sid_name'] = self.resolve_sid(ace_copy['sid'], skip_well_known=skip_well_known)
                translated_dacl.append(ace_copy)
            result['dacl'] = translated_dacl
        
        # SACL übersetzen
        if result.get('sacl'):
            translated_sacl = []
            for ace in result['sacl']:
                ace_copy = ace.copy()
                if 'sid' in ace_copy:
                    ace_copy['sid_name'] = self.resolve_sid(ace_copy['sid'], skip_well_known=skip_well_known)
                translated_sacl.append(ace_copy)
            result['sacl'] = translated_sacl
        
        return result