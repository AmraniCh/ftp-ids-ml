from abc import ABC, abstractmethod

class BaseParser(ABC):
    """Base parser contract that every FTP daemon parser must follow"""
    
    name: str = "base"

    @abstractmethod
    def parse_line(self, line: str) -> dict | None:
        """Parses a log line and returns the details in a dictionary
        
        returns: timestamp, PID, user, event_type, src_ip, 
                 command, argument, response_code, filename, filesize,
                 speed, session_end, abrupt_end, raw_line
        """
        ...
