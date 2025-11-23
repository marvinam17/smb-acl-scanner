from ldap3 import Connection, Server, ALL, NTLM
from .well_known_sids import WellKnownSIDs

class LDAPResolver(WellKnownSIDs):
    """Klasse zur Auflösung von SIDs über LDAP"""
    
    def __init__(self, ldap_server, ldap_user, ldap_password, domain, further_well_known_sids=None):
        """
        Initialisiert den LDAP Resolver
        
        Args:
            ldap_server: LDAP Server Adresse
            ldap_user: LDAP Benutzername
            ldap_password: LDAP Passwort
            domain: Domain (z.B. 'example.com')
            further_well_known_sids: Zusätzliche well-known SIDs als Dictionary
        """
        # Basisklasse initialisieren
        super().__init__(additional_well_known_sids=further_well_known_sids)
        
        self.ldap_server = ldap_server
        self.ldap_user = ldap_user
        self.ldap_password = ldap_password
        self.domain = domain
        self.connection = None
        self.sid_cache = {}
    
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
            if skip_well_known and self.is_well_known_sid(sid):
                return sid
            return cached_value
        
        # Well-known SIDs
        if self.is_well_known_sid(sid):
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
                if skip_well_known and self.is_well_known_sid(sid):
                    result[sid] = sid
                else:
                    result[sid] = self.sid_cache[sid]
            elif self.is_well_known_sid(sid):
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
            skip_well_known: Wenn True, werden well-known SIDs komplett aus den Ergebnissen entfernt
            
        Returns:
            Generator von Dictionaries mit übersetzten SIDs
            
        Beispiel:
            reader = SMBACLReader("user", "pass", "DOMAIN")
            resolver = LDAPResolver("ldap.example.com", "user", "pass", "example.com")
            resolver.connect()
            
            scan_results = reader.scan_acl_changes("\\\\server\\share")
            translated = resolver.translate_acl_scan_results(scan_results, skip_well_known=True)
            
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
            skip_well_known: Wenn True, werden well-known SIDs komplett aus den Ergebnissen entfernt
            
        Returns:
            Security-Info Dictionary mit zusätzlichen '*_name' Feldern für übersetzte SIDs
        """
        # Kopie erstellen, um Original nicht zu verändern
        result = security_info.copy()
        
        # Wenn skip_well_known, well-known SIDs aus ACLs filtern
        if skip_well_known:
            result = self.filter_well_known_from_security_info(result)
        
        # Owner übersetzen
        if result.get('owner'):
            result['owner_name'] = self.resolve_sid(result['owner'], skip_well_known=False)
        
        # Group übersetzen
        if result.get('group'):
            result['group_name'] = self.resolve_sid(result['group'], skip_well_known=False)
        
        # DACL übersetzen
        if result.get('dacl'):
            translated_dacl = []
            for ace in result['dacl']:
                ace_copy = ace.copy()
                if 'sid' in ace_copy:
                    ace_copy['sid_name'] = self.resolve_sid(ace_copy['sid'], skip_well_known=False)
                translated_dacl.append(ace_copy)
            result['dacl'] = translated_dacl
        
        # SACL übersetzen
        if result.get('sacl'):
            translated_sacl = []
            for ace in result['sacl']:
                ace_copy = ace.copy()
                if 'sid' in ace_copy:
                    ace_copy['sid_name'] = self.resolve_sid(ace_copy['sid'], skip_well_known=False)
                translated_sacl.append(ace_copy)
            result['sacl'] = translated_sacl
        
        return result