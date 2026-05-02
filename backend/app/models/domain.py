from sqlalchemy import String, Integer, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime, timezone

from app.core.database import Base


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False, index=True
    )

    domain: Mapped[str] = mapped_column(
        String(253), unique=True, nullable=False, index=True
    )

    # Per-domain Linux system user that owns this domain's webroot.
    # Derived deterministically from the domain name at creation time.
    # Null for records that pre-date the isolation feature (legacy compat).
    linux_username: Mapped[str | None] = mapped_column(
        String(32), unique=True, nullable=True, index=True
    )

    document_root: Mapped[str] = mapped_column(String(512), nullable=False)

    php_version: Mapped[str] = mapped_column(String(8), default="8.1")

    ssl_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    ssl_expiry: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    is_parked: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_domain_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("domains.id"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    subdomains: Mapped[list["Domain"]] = relationship(
        "Domain", back_populates="parent"
    )
    parent: Mapped["Domain | None"] = relationship(
        "Domain", back_populates="subdomains", remote_side=[id]
    )
