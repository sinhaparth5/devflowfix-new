"""Merge user_details and PR management branches

Revision ID: 7d1ffddce18c
Revises: 7534e5173df0, 164f58140f5e
Create Date: 2025-12-15 11:20:22.299375

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7d1ffddce18c'
down_revision: Union[str, Sequence[str], None] = ('7534e5173df0', '164f58140f5e')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
