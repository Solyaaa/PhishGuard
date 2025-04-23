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
                 user_id: Optional[str] = None,
                 created_at: Optional[datetime] = None,
                 _id: Optional[Union[str, ObjectId]] = None):
        """
        Ініціалізує новий результат перевірки.

        Args:
            url: URL, який був перевірений
            domain: Домен URL
            checks: Список результатів перевірок
            final_score: Фінальний показник безпеки (0-100)
            is_phishing: Чи класифіковано URL як фішинговий
            ip_address: IP-адреса користувача, який ініціював перевірку
            user_id: ID зареєстрованого користувача (якщо є)
            created_at: Час перевірки
            _id: ID документа MongoDB
        """
        self.url = url
        self.domain = domain
        self.checks = checks
        self.final_score = final_score
        self.is_phishing = is_phishing
        self.ip_address = ip_address
        self.user_id = user_id
        self.created_at = created_at or datetime.utcnow()
        self._id = _id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanResult':
        """Створює ScanResult зі словника."""
        return cls(
            url=data['url'],
            domain=data['domain'],
            checks=data['checks'],
            final_score=data['final_score'],
            is_phishing=data['is_phishing'],
            ip_address=data.get('ip_address'),
            user_id=data.get('user_id'),
            created_at=data.get('created_at'),
            _id=data.get('_id')
        )

    def to_dict(self) -> Dict[str, Any]:
        """Перетворює ScanResult у словник для зберігання в MongoDB."""
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

        if self.user_id:
            result['user_id'] = self.user_id

        if self._id:
            result['_id'] = self._id

        return result


class UserFeedback:
    """
    Модель для відгуків користувачів про результати перевірок.
    """

    def __init__(self,
                 scan_id: Union[str, ObjectId],
                 feedback_type: str,
                 comment: Optional[str] = None,
                 ip_address: Optional[str] = None,
                 user_id: Optional[str] = None,
                 created_at: Optional[datetime] = None,
                 _id: Optional[Union[str, ObjectId]] = None):
        """
        Ініціалізує новий запис відгуку користувача.

        Args:
            scan_id: ID перевірки, якої стосується відгук
            feedback_type: Тип відгуку (false_positive, false_negative, тощо)
            comment: Додатковий коментар користувача
            ip_address: IP-адреса користувача
            user_id: ID зареєстрованого користувача (якщо є)
            created_at: Час надання відгуку
            _id: ID документа MongoDB
        """
        self.scan_id = scan_id if isinstance(scan_id, ObjectId) else ObjectId(scan_id)
        self.feedback_type = feedback_type
        self.comment = comment
        self.ip_address = ip_address
        self.user_id = user_id
        self.created_at = created_at or datetime.utcnow()
        self._id = _id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserFeedback':
        """Створює UserFeedback зі словника."""
        return cls(
            scan_id=data['scan_id'],
            feedback_type=data['feedback_type'],
            comment=data.get('comment'),
            ip_address=data.get('ip_address'),
            user_id=data.get('user_id'),
            created_at=data.get('created_at'),
            _id=data.get('_id')
        )

    def to_dict(self) -> Dict[str, Any]:
        """Перетворює UserFeedback у словник для зберігання в MongoDB."""
        result = {
            'scan_id': self.scan_id,
            'feedback_type': self.feedback_type,
            'created_at': self.created_at
        }

        if self.comment:
            result['comment'] = self.comment

        if self.ip_address:
            result['ip_address'] = self.ip_address

        if self.user_id:
            result['user_id'] = self.user_id

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
                 reporter_id: Optional[str] = None,
                 comment: Optional[str] = None,
                 verified: bool = False,
                 verification_date: Optional[datetime] = None,
                 created_at: Optional[datetime] = None,
                 _id: Optional[Union[str, ObjectId]] = None):
        """
        Ініціалізує новий повідомлений домен.

        Args:
            domain: Повідомлений домен
            url: Повний URL, який був повідомлений
            reporter_ip: IP-адреса заявника
            reporter_id: ID зареєстрованого користувача, який повідомив (якщо є)
            comment: Додатковий коментар користувача
            verified: Чи був повідомлення перевірено
            verification_date: Коли повідомлення було перевірено
            created_at: Коли повідомлення було створено
            _id: ID документа MongoDB
        """
        self.domain = domain
        self.url = url
        self.reporter_ip = reporter_ip
        self.reporter_id = reporter_id
        self.comment = comment
        self.verified = verified
        self.verification_date = verification_date
        self.created_at = created_at or datetime.utcnow()
        self._id = _id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReportedDomain':
        """Створює ReportedDomain зі словника."""
        return cls(
            domain=data['domain'],
            url=data['url'],
            reporter_ip=data.get('reporter_ip'),
            reporter_id=data.get('reporter_id'),
            comment=data.get('comment'),
            verified=data.get('verified', False),
            verification_date=data.get('verification_date'),
            created_at=data.get('created_at'),
            _id=data.get('_id')
        )

    def to_dict(self) -> Dict[str, Any]:
        """Перетворює ReportedDomain у словник для зберігання в MongoDB."""
        result = {
            'domain': self.domain,
            'url': self.url,
            'verified': self.verified,
            'created_at': self.created_at
        }

        if self.reporter_ip:
            result['reporter_ip'] = self.reporter_ip

        if self.reporter_id:
            result['reporter_id'] = self.reporter_id

        if self.comment:
            result['comment'] = self.comment

        if self.verification_date:
            result['verification_date'] = self.verification_date

        if self._id:
            result['_id'] = self._id

        return result


