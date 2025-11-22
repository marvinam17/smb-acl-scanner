from ldap3 import Connection, Server, ALL, NTLM

class LDAPResolver:
    """Klasse zur Auflösung von SIDs über LDAP"""
    
    def __init__(self, ldap_server, ldap_user, ldap_password, domain):
        """
        Initialisiert den LDAP Resolver
        
        Args:
            ldap_server: LDAP Server Adresse
            ldap_user: LDAP Benutzername
            ldap_password: LDAP Passwort
            domain: Domain (z.B. 'example.com')
        """
        self.ldap_server = ldap_server
        self.ldap_user = ldap_user
        self.ldap_password = ldap_password
        self.domain = domain
        self.connection = None
        self.sid_cache = {}
        
        # Well-known SIDs
        self.well_known_sids = {
            'S-1-1-0': 'Everyone',
            'S-1-5-18': 'NT AUTHORITY\\SYSTEM',
            'S-1-5-19': 'NT AUTHORITY\\LOCAL SERVICE',
            'S-1-5-20': 'NT AUTHORITY\\NETWORK SERVICE',
            'S-1-5-32-544': 'BUILTIN\\Administrators',
            'S-1-5-32-545': 'BUILTIN\\Users',
            'S-1-5-32-546': 'BUILTIN\\Guests',
            'S-1-5-32-547': 'BUILTIN\\Power Users',
            'S-1-5-32-548': 'BUILTIN\\Account Operators',
            'S-1-5-32-549': 'BUILTIN\\Server Operators',
            'S-1-5-32-550': 'BUILTIN\\Print Operators',
            'S-1-5-32-551': 'BUILTIN\\Backup Operators',
            'S-1-5-32-552': 'BUILTIN\\Replicators',
        }
    
    def connect(self):
        """Verbindung zum LDAP-Server herstellen"""
        server = Server(self.ldap_server, get_info=ALL)
        
        # NTLM-Authentifizierung verwenden
        user = f"{self.domain}\\{self.ldap_user}"
        self.connection = Connection(
            server,
            user=user,
            password=self.ldap_password,
            authentication=NTLM,
            auto_bind=True
        )
    
    def disconnect(self):
        """LDAP-Verbindung trennen"""
        if self.connection:
            self.connection.unbind()
    
    def resolve_sid(self, sid):
        """
        Löst eine SID zu einem lesbaren Namen auf
        
        Args:
            sid: SID als String (z.B. "S-1-5-21-...")
            
        Returns:
            Name des Benutzers/der Gruppe oder die SID, falls nicht gefunden
        """
        # Cache prüfen
        if sid in self.sid_cache:
            return self.sid_cache[sid]
        
        # Well-known SIDs
        if sid in self.well_known_sids:
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
                
                # Domain hinzufügen
                resolved_name = f"{self.domain.upper()}\\{name}"
                self.sid_cache[sid] = resolved_name
                return resolved_name
            else:
                # Nicht gefunden, SID zurückgeben
                self.sid_cache[sid] = sid
                return sid
                
        except Exception as e:
            print(f"LDAP-Abfrage fehlgeschlagen für {sid}: {e}")
            self.sid_cache[sid] = sid
            return sid
    
    def resolve_multiple_sids(self, sids):
        """
        Löst mehrere SIDs gleichzeitig auf (Performance-Optimierung)
        
        Args:
            sids: Liste von SIDs
            
        Returns:
            Dictionary mit SID -> Name Mapping
        """
        result = {}
        unknown_sids = []
        
        # Zuerst Cache und Well-known SIDs prüfen
        for sid in sids:
            if sid in self.sid_cache:
                result[sid] = self.sid_cache[sid]
            elif sid in self.well_known_sids:
                result[sid] = self.well_known_sids[sid]
                self.sid_cache[sid] = self.well_known_sids[sid]
            else:
                unknown_sids.append(sid)
        
        # Unbekannte SIDs einzeln auflösen
        for sid in unknown_sids:
            result[sid] = self.resolve_sid(sid)
        
        return result