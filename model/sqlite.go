package model

import (
	"database/sql"
	"github.com/fadhilthomas/go-nuclei-reporter/config"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"os"
)

func InitSqliteDB() (database *sql.DB, err error) {
	dbFile := config.GetStr(config.DATABASE_LOCATION)
	if _, err = os.Stat(dbFile); err == nil {
		err = os.Remove(dbFile)
		if err != nil {
			return nil, errors.New(err.Error())
		}
		log.Debug().Str("file", "sqlite").Msg("remove database")
	} else if os.IsNotExist(err) {
		return nil, errors.New(err.Error())
	} else {
		return nil, errors.New(err.Error())
	}

	log.Debug().Str("file", "sqlite").Msg("creating database")
	file, err := os.Create(dbFile)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	log.Info().Str("file", "sqlite").Msg("success to create database")
	_ = file.Close()

	sqlDatabase, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	err = createTable(sqlDatabase)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	if sqlDatabase != nil {
		return sqlDatabase, nil
	} else {
		return nil, errors.New(err.Error())
	}
}

func OpenSqliteDB() (db *sql.DB, err error) {
	dbFile := config.GetStr(config.DATABASE_LOCATION)
	sqlDatabase, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	return sqlDatabase, nil
}

func createTable(db *sql.DB) error {
	vulnerabilityTable := `CREATE TABLE "vulnerability" (
		"vulnerability_id"		INTEGER NOT NULL,
		"vulnerability_name"	TEXT NOT NULL,
		"vulnerability_host"	TEXT NOT NULL,
		"vulnerability_status"	TEXT NOT NULL,
		PRIMARY KEY("vulnerability_id" AUTOINCREMENT)
	);`

	err := execSQL(db, "vulnerability", vulnerabilityTable)
	if err != nil {
		return errors.New(err.Error())
	}

	return nil
}

func execSQL(db *sql.DB, tableName string, tableSQL string) (err error) {
	log.Debug().Str("file", "sqlite").Msgf("creating %s table", tableName)
	statement, err := db.Prepare(tableSQL)
	if err != nil {
		return errors.New(err.Error())
	}
	_, err = statement.Exec()
	if err != nil {
		return errors.New(err.Error())
	}
	log.Info().Str("file", "sqlite").Msgf("success to create %s table", tableName)
	return nil
}

func QuerySqliteVulnerability(db *sql.DB, vulnerabilityName string, vulnerabilityHost string) (output string, err error) {
	selectSQL := `SELECT vulnerability_status FROM vulnerability WHERE vulnerability_name=$1 AND vulnerability_host=$2;`
	row, err := db.Query(selectSQL, vulnerabilityName, vulnerabilityHost)
	if err != nil {
		return "", errors.New(err.Error())
	}
	defer row.Close()
	for row.Next() {
		if err = row.Scan(&output); err != nil {
			return "", errors.New(err.Error())
		}
	}

	switch {
	case output == "open":
		return "still-open", nil
	case output == "close":
		return "re-open", nil
	default:
		return "new", nil
	}
}

func InsertSqliteVulnerability(db *sql.DB, vulnerabilityName string, vulnerabilityHost string, vulnerabilityStatus string) error {
	insertSql := `INSERT INTO vulnerability (vulnerability_name, vulnerability_host, vulnerability_status) VALUES (?, ?, ?)`
	statement, err := db.Prepare(insertSql)
	if err != nil {
		return errors.New(err.Error())
	}
	_, err = statement.Exec(vulnerabilityName, vulnerabilityHost, vulnerabilityStatus)
	if err != nil {
		return errors.New(err.Error())
	}
	return nil
}

func UpdateSqliteVulnerabilityStatus(db *sql.DB, vulnerabilityName string, vulnerabilityHost string, vulnerabilityStatus string) error {
	updateSql := `UPDATE vulnerability SET vulnerability_status = ? WHERE vulnerability_name = ? AND vulnerability_host = ?`
	statement, err := db.Prepare(updateSql)
	if err != nil {
		return errors.New(err.Error())
	}
	_, err = statement.Exec(vulnerabilityStatus, vulnerabilityName, vulnerabilityHost)
	if err != nil {
		return errors.New(err.Error())
	}
	return nil
}

func UpdateSqliteVulnerabilityStatusAll(db *sql.DB) error {
	updateSql := `UPDATE vulnerability SET vulnerability_status = 'close' WHERE 1 = 1`
	statement, err := db.Prepare(updateSql)
	if err != nil {
		return errors.New(err.Error())
	}
	_, err = statement.Exec()
	if err != nil {
		return errors.New(err.Error())
	}
	return nil
}
