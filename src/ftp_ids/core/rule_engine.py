from pprint import pprint

class RuleEngine:

    def __init__(self, session):
        self.session = session

    def check(self):
        return [{
            'rule_id': 'VSFTPD_234_BACKDOOR',
            'name': "vsftpd 2.3.4 Backdoor (CVE-2011-2523)",
            'matched': self._backdoor()
        }, {
            'rule_id': 'FTP_BOUNCE_MGLNDD',
            'name': "FTP bounce probe (MGLNDD scanner)",
            'matched': self._ftp_bounce(),
        }, {
            'rule_id': 'PORT_SCAN',
            'name': "Port scan",
            'matched': self._port_scan(),
        },]

    def _backdoor(self):
        for event in self.session['events']:
            if (event['command'] == "USER"
                and event['argument'] 
                and event['argument'].find(":)") != -1):
                return True
                
        return False
    

    def _port_scan(self):
        has_command = any(
            e['event_type'] == 'FTP command' for e in self.session['events'] 
        )
        return not has_command and len(self.session['events']) >= 2
    
    def _ftp_bounce(self):
        for event in self.session['events']:
            if (event['command'] and event['command'].find("MGLNDD_") != -1):
                return True

        return False

