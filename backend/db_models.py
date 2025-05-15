from datetime import datetime
from bson import ObjectId
from typing import Optional, List, Dict, Any, Union


class ScanResult:
    """
    Модель для результатів перевірки на фішинг у MongoDB.
    """

    def __init__(self,
                 url: str,
                 domain: str,
                 checks: List[Dict[str, Any]],
                 final_score: int,
                 is_phishing: bool,
                 ip_address: Optional[str] = None,
                 created_at: Optional[datetime] = None,
                 _id: Optional[Union[str, ObjectId]] = None):
        self.url = url
        self.domain = domain
        self.checks = checks
        self.final_score = final_score
        self.is_phishing = is_phishing
        self.ip_address = ip_address
        self.created_at = created_at or datetime.utcnow()
        self._id = _id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanResult':
        return cls(
            url=data['url'],
            domain=data['domain'],
            checks=data['checks'],
            final_score=data['final_score'],
            is_phishing=data['is_phishing'],
            ip_address=data.get('ip_address'),
            created_at=data.get('created_at'),
            _id=data.get('_id')
        )

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'url': self.url,
            'domain': self.domain,
            'checks': self.checks,
            'final_score': self.final_score,
            'is_phishing': self.is_phishing,
            'created_at': self.created_at
        }
        if self.ip_address:
            result['ip_address'] = self.ip_address
        if self._id:
            result['_id'] = self._id
        return result


class ReportedDomain:
    """
    Модель для доменів, які користувачі повідомили як фішингові.
    """

    def __init__(self,
                 domain: str,
                 url: str,
                 reporter_ip: Optional[str] = None,
                 comment: Optional[str] = None,
                 created_at: Optional[datetime] = None,
                 _id: Optional[Union[str, ObjectId]] = None):
        self.domain = domain
        self.url = url
        self.reporter_ip = reporter_ip
        self.comment = comment
        self.created_at = created_at or datetime.utcnow()
        self._id = _id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReportedDomain':
        return cls(
            domain=data['domain'],
            url=data['url'],
            reporter_ip=data.get('reporter_ip'),
            comment=data.get('comment'),
            created_at=data.get('created_at'),
            _id=data.get('_id')
        )

    def to_dict(self) -> Dict[str, Any]:
        result = {
            'domain': self.domain,
            'url': self.url,
            'created_at': self.created_at
        }
        if self.reporter_ip:
            result['reporter_ip'] = self.reporter_ip
        if self.comment:
            result['comment'] = self.comment
        if self._id:
            result['_id'] = self._id
        return result
