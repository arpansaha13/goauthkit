package repository

import (
	"context"

	"gorm.io/gorm"
)

// QueryDB is the GORM surface repositories need. *gorm.DB implements it.
type QueryDB interface {
	WithContext(ctx context.Context) *gorm.DB
}
