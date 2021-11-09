package main

import (
	"github.com/fadhilthomas/go-nuclei-reporter/model"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

func main() {
	_, err := model.InitSqliteDB()
	if err != nil {
		log.Error().Stack().Err(errors.New(err.Error())).Msg("")
	}
}
