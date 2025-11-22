"""
SMB ACL Reader Module
Liest Windows ACLs von NTFS über SMB Protokoll
"""

import smbclient
from smbprotocol.file_info import InfoType
from smbprotocol.open import (
    DirectoryAccessMask,
    FilePipePrinterAccessMask,
    SMB2QueryInfoRequest,
    SMB2QueryInfoResponse,
)
from smbprotocol.security_descriptor import SMB2CreateSDBuffer


class SecurityInfo:
    """Security Information Flags"""
    Owner = 0x00000001
    Group = 0x00000002
    Dacl = 0x00000004
    Sacl = 0x00000008
    Label = 0x00000010
    Attribute = 0x00000020
    Scope = 0x00000040
    Backup = 0x00010000


class SMBACLReader:
    """Klasse zum Auslesen von Windows ACLs über SMB"""
    
    def __init__(self, username, password, domain="", auth_protocol="ntlm"):
        """
        Initialisiert den ACL Reader
        
        Args:
            username: SMB Benutzername
            password: SMB Passwort
            domain: Domain (optional)
        """
        # SMB Client konfigurieren
        smbclient.ClientConfig(
            username=username,
            password=password,
            domain=domain if domain else None,
            auth_protocol=auth_protocol
        )
    
    def scan_directory(self, base_path, recursive=True, max_depth=None, include_files=True, include_dirs=True):
        """
        Scannt ein Verzeichnis und extrahiert ACLs für alle Dateien/Ordner
        
        Args:
            base_path: UNC-Pfad zum Basis-Verzeichnis
            recursive: Rekursiv in Unterverzeichnisse gehen
            max_depth: Maximale Tiefe (None = unbegrenzt, 0 = nur base_path, 1 = base_path + direkte Kinder)
            include_files: Dateien einbeziehen
            include_dirs: Verzeichnisse einbeziehen
            
        Returns:
            Generator der Dictionaries mit 'path', 'type', 'security' Informationen
        """
        yield from self._scan_directory_recursive(base_path, 0, max_depth, include_files, include_dirs, recursive)
    
    def _scan_directory_recursive(self, path, current_depth, max_depth, include_files, include_dirs, recursive):
        """Interne rekursive Scan-Methode"""
        
        # Maximale Tiefe erreicht?
        if max_depth is not None and current_depth > max_depth:
            return
        
        # Aktuelles Verzeichnis selbst verarbeiten (wenn gewünscht und nicht bei Tiefe 0)
        if include_dirs and current_depth > 0:
            try:
                sd = self.get_security_descriptor(path, 'dir')
                sec_info = self.parse_security_descriptor(sd)
                yield {
                    'path': path,
                    'type': 'directory',
                    'depth': current_depth,
                    'security': sec_info
                }
            except Exception as e:
                yield {
                    'path': path,
                    'type': 'directory',
                    'depth': current_depth,
                    'error': str(e)
                }
        
        # Verzeichnisinhalt auflisten
        try:
            entries = smbclient.scandir(path)
        except Exception as e:
            print(f"Fehler beim Scannen von {path}: {e}")
            return
        
        for entry in entries:
            full_path = f"{path}\\{entry.name}"
            
            # Verzeichnis
            if entry.is_dir():
                # Rekursiv weitermachen wenn gewünscht
                if recursive:
                    yield from self._scan_directory_recursive(
                        full_path, 
                        current_depth + 1, 
                        max_depth, 
                        include_files, 
                        include_dirs,
                        recursive
                    )
                # Oder nur das Verzeichnis selbst
                elif include_dirs:
                    try:
                        sd = self.get_security_descriptor(full_path, 'dir')
                        sec_info = self.parse_security_descriptor(sd)
                        yield {
                            'path': full_path,
                            'type': 'directory',
                            'depth': current_depth + 1,
                            'security': sec_info
                        }
                    except Exception as e:
                        yield {
                            'path': full_path,
                            'type': 'directory',
                            'depth': current_depth + 1,
                            'error': str(e)
                        }
            
            # Datei
            elif entry.is_file() and include_files:
                try:
                    sd = self.get_security_descriptor(full_path, 'file')
                    sec_info = self.parse_security_descriptor(sd)
                    yield {
                        'path': full_path,
                        'type': 'file',
                        'depth': current_depth + 1,
                        'size': entry.stat().st_size,
                        'security': sec_info
                    }
                except Exception as e:
                    yield {
                        'path': full_path,
                        'type': 'file',
                        'depth': current_depth + 1,
                        'error': str(e)
                    }
    
    def scan_directory_to_list(self, base_path, recursive=True, max_depth=None, include_files=True, include_dirs=True):
        """
        Wie scan_directory, aber gibt eine Liste statt Generator zurück
        
        Returns:
            Liste von Dictionaries mit ACL-Informationen
        """
        return list(self.scan_directory(base_path, recursive, max_depth, include_files, include_dirs))
    
    def export_acls_to_dict(self, base_path, recursive=True, max_depth=None):
        """
        Exportiert alle ACLs in ein verschachteltes Dictionary-Format
        
        Returns:
            Dictionary mit Pfad als Key und ACL-Info als Value
        """
        result = {}
        for item in self.scan_directory(base_path, recursive, max_depth, True, True):
            result[item['path']] = {
                'type': item['type'],
                'depth': item['depth'],
                'security': item.get('security'),
                'error': item.get('error')
            }
        return result
    
    def get_security_descriptor(self, file_path, file_type='file'):
        """
        Liest den Security Descriptor einer Datei oder eines Ordners
        
        Args:
            file_path: UNC-Pfad zur Datei
            file_type: 'file' für Dateien, 'dir' für Ordner
            
        Returns:
            SMB2CreateSDBuffer Objekt mit Security Descriptor
        """
        # Desired Access basierend auf Typ
        if file_type == 'dir':
            desired_access = DirectoryAccessMask.READ_CONTROL
            mode = 'br'
        else:
            desired_access = FilePipePrinterAccessMask.READ_CONTROL
            mode = 'rb'
        
        # Datei/Ordner öffnen und Security Descriptor abfragen
        with smbclient.open_file(
            file_path,
            mode=mode,
            buffering=0,
            file_type=file_type,
            desired_access=desired_access
        ) as fd:
            sd = self._get_sd(
                fd.fd,
                SecurityInfo.Owner | SecurityInfo.Group | SecurityInfo.Dacl
            )
            return sd
    
    def get_security_descriptor_with_sacl(self, file_path, file_type='file'):
        """
        Liest den Security Descriptor inklusive SACL (benötigt spezielle Berechtigungen)
        
        Args:
            file_path: UNC-Pfad zur Datei
            file_type: 'file' für Dateien, 'dir' für Ordner
            
        Returns:
            SMB2CreateSDBuffer Objekt mit Security Descriptor
        """
        if file_type == 'dir':
            desired_access = (DirectoryAccessMask.READ_CONTROL | 
                            DirectoryAccessMask.ACCESS_SYSTEM_SECURITY)
            mode = 'br'
        else:
            desired_access = (FilePipePrinterAccessMask.READ_CONTROL |
                            FilePipePrinterAccessMask.ACCESS_SYSTEM_SECURITY)
            mode = 'rb'
        
        with smbclient.open_file(
            file_path,
            mode=mode,
            buffering=0,
            file_type=file_type,
            desired_access=desired_access
        ) as fd:
            sd = self._get_sd(
                fd.fd,
                SecurityInfo.Owner | SecurityInfo.Group | 
                SecurityInfo.Dacl | SecurityInfo.Sacl
            )
            return sd
    
    def _get_sd(self, fd, info):
        """
        Interne Methode zum Abrufen des Security Descriptors
        
        Args:
            fd: File descriptor vom smbclient
            info: SecurityInfo Flags
            
        Returns:
            SMB2CreateSDBuffer Objekt
        """
        query_req = SMB2QueryInfoRequest()
        query_req['info_type'] = InfoType.SMB2_0_INFO_SECURITY
        query_req['output_buffer_length'] = 65535
        query_req['additional_information'] = info
        query_req['file_id'] = fd.file_id
        
        req = fd.connection.send(
            query_req,
            sid=fd.tree_connect.session.session_id,
            tid=fd.tree_connect.tree_connect_id
        )
        resp = fd.connection.receive(req)
        
        query_resp = SMB2QueryInfoResponse()
        query_resp.unpack(resp['data'].get_value())
        
        security_descriptor = SMB2CreateSDBuffer()
        security_descriptor.unpack(query_resp['buffer'].get_value())
        
        return security_descriptor
    
    def parse_security_descriptor(self, sd):
        """
        Parst einen Security Descriptor in ein lesbares Format
        
        Args:
            sd: SMB2CreateSDBuffer Objekt
            
        Returns:
            Dictionary mit Owner, Group, DACL und SACL
        """
        result = {
            'owner': None,
            'group': None,
            'dacl': [],
            'sacl': []
        }
        
        # Owner und Group extrahieren
        owner = sd.get_owner()
        if owner:
            result['owner'] = str(owner)
        
        group = sd.get_group()
        if group:
            result['group'] = str(group)
        
        # DACL extrahieren
        try:
            dacl = sd.get_dacl()
            if dacl and hasattr(dacl, 'fields') and 'aces' in dacl.fields:
                # ACL ist ein smbprotocol Structure Objekt mit 'aces' field
                aces = dacl['aces']
                if aces and hasattr(aces, 'get_value'):
                    # aces ist ein ListField
                    for ace in aces.get_value():
                        result['dacl'].append({
                            'type': str(ace['ace_type'].get_value() if hasattr(ace['ace_type'], 'get_value') else ace['ace_type']),
                            'flags': ace['ace_flags'].get_value() if hasattr(ace['ace_flags'], 'get_value') else ace['ace_flags'],
                            'mask': ace['mask'].get_value() if hasattr(ace['mask'], 'get_value') else ace['mask'],
                            'sid': str(ace['sid']),
                            'permissions': self._mask_to_permissions(
                                ace['mask'].get_value() if hasattr(ace['mask'], 'get_value') else ace['mask']
                            )
                        })
        except Exception as e:
            print(f"Warnung: DACL konnte nicht geparst werden: {e}")
        
        # SACL extrahieren
        try:
            sacl = sd.get_sacl()
            if sacl and hasattr(sacl, 'fields') and 'aces' in sacl.fields:
                aces = sacl['aces']
                if aces and hasattr(aces, 'get_value'):
                    for ace in aces.get_value():
                        result['sacl'].append({
                            'type': str(ace['ace_type'].get_value() if hasattr(ace['ace_type'], 'get_value') else ace['ace_type']),
                            'flags': ace['ace_flags'].get_value() if hasattr(ace['ace_flags'], 'get_value') else ace['ace_flags'],
                            'mask': ace['mask'].get_value() if hasattr(ace['mask'], 'get_value') else ace['mask'],
                            'sid': str(ace['sid']),
                            'permissions': self._mask_to_permissions(
                                ace['mask'].get_value() if hasattr(ace['mask'], 'get_value') else ace['mask']
                            )
                        })
        except Exception as e:
            print(f"Warnung: SACL konnte nicht geparst werden: {e}")
        
        return result
    
    def _mask_to_permissions(self, mask):
        """
        Konvertiert Access Mask zu lesbaren Berechtigungen
        
        Args:
            mask: Integer Access Mask
            
        Returns:
            Liste von Berechtigungs-Strings
        """
        permissions = []
        
        # Standard-Rechte
        if mask & 0x00010000:
            permissions.append('DELETE')
        if mask & 0x00020000:
            permissions.append('READ_CONTROL')
        if mask & 0x00040000:
            permissions.append('WRITE_DAC')
        if mask & 0x00080000:
            permissions.append('WRITE_OWNER')
        if mask & 0x00100000:
            permissions.append('SYNCHRONIZE')
        
        # Datei-spezifische Rechte
        if mask & 0x00000001:
            permissions.append('FILE_READ_DATA')
        if mask & 0x00000002:
            permissions.append('FILE_WRITE_DATA')
        if mask & 0x00000004:
            permissions.append('FILE_APPEND_DATA')
        if mask & 0x00000008:
            permissions.append('FILE_READ_EA')
        if mask & 0x00000010:
            permissions.append('FILE_WRITE_EA')
        if mask & 0x00000020:
            permissions.append('FILE_EXECUTE')
        if mask & 0x00000080:
            permissions.append('FILE_READ_ATTRIBUTES')
        if mask & 0x00000100:
            permissions.append('FILE_WRITE_ATTRIBUTES')
        
        # Generic Rights
        if mask & 0x10000000:
            permissions.append('GENERIC_ALL')
        if mask & 0x20000000:
            permissions.append('GENERIC_EXECUTE')
        if mask & 0x40000000:
            permissions.append('GENERIC_WRITE')
        if mask & 0x80000000:
            permissions.append('GENERIC_READ')
        
        return permissions