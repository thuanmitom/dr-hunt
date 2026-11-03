"""Importing this package registers every table on ``Base.metadata`` (used by Alembic)."""

from app.db.models.ai_compilation import AiCompilation
from app.db.models.hunting_pack import HuntingPack
from app.db.models.pivoted_cluster import PivotedCluster, cluster_event_links
from app.db.models.raw_intel_event import RawIntelEvent
from app.db.models.reference_dataset import ReferenceDataset
from app.db.models.telegram_digest import TelegramDigest
from app.db.models.tenant import Tenant

__all__ = [
    "AiCompilation",
    "HuntingPack",
    "PivotedCluster",
    "RawIntelEvent",
    "ReferenceDataset",
    "TelegramDigest",
    "Tenant",
    "cluster_event_links",
]
