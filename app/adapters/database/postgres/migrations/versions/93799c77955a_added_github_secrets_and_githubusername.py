"""added github secrets and githubusername

Revision ID: 93799c77955a
Revises: 01441d9529c0
Create Date: 2025-11-25 13:54:09.276759

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '93799c77955a'
down_revision: Union[str, Sequence[str], None] = '01441d9529c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
