package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"github.com/fadhilthomas/go-nuclei-reporter/config"
	"github.com/fadhilthomas/go-nuclei-reporter/model"
	"github.com/jomei/notionapi"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
	"go.uber.org/ratelimit"
	"os"
)

var (
	slackAttachmentList      []model.SlackAttachmentBody
	slackBlockList           []model.SlackBlockBody
	vulnerabilityList        []model.Output
	notionPageList           []notionapi.Page
	sqlDatabase              *sql.DB
	slackVulnerabilityStatus string
	notionDatabase           *notionapi.Client
)

func main() {
	config.Set(config.LOG_LEVEL, "info")
	if config.GetStr(config.LOG_LEVEL) == "debug" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	rl := ratelimit.New(1)

	databaseType := config.GetStr(config.DATABASE_TYPE)
	slackToken := config.GetStr(config.SLACK_TOKEN)

	if databaseType == "sqlite" {
		sqlDatabase, err := model.OpenSqliteDB()
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}
		if sqlDatabase == nil {
			return
		}
		err = model.UpdateSqliteVulnerabilityStatusAll(sqlDatabase)
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}
	} else if databaseType == "notion" {
		notionDatabase = model.OpenNotionDB()

		rl.Take()
		notionQueryStatusResult, err := model.QueryNotionVulnerabilityStatus(notionDatabase, "open")
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}
		for _, notionPage := range notionQueryStatusResult {
			rl.Take()
			_, err := model.UpdateNotionVulnerabilityStatus(notionDatabase, notionPage.ID.String(), "close")
			if err != nil {
				log.Error().Stack().Err(errors.New(err.Error())).Msg("")
				return
			}
		}
	}

	summaryReportSeverity := model.SummaryReportSeverity{}
	summaryReportStatus := model.SummaryReportStatus{}

	fileReport, err := os.Open(config.GetStr(config.FILE_LOCATION))
	if err != nil {
		log.Error().Stack().Err(errors.New(err.Error())).Msg("")
		return
	}
	fScanner := bufio.NewScanner(fileReport)
	for fScanner.Scan() {
		detailReport := model.Output{}
		err = json.Unmarshal([]byte(fScanner.Text()), &detailReport)
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}

		vulnerabilityList = append(vulnerabilityList, detailReport)

		switch detailReport.Info.Severity {
		case "critical":
			summaryReportSeverity.Critical++
		case "high":
			summaryReportSeverity.High++
		case "medium":
			summaryReportSeverity.Medium++
		case "low":
			summaryReportSeverity.Low++
		case "info":
			summaryReportSeverity.Info++
		}

		slackVulnerabilityStatus = ""

		if databaseType == "sqlite" {
			sqlQueryNameResult, _ := model.QuerySqliteVulnerability(sqlDatabase, detailReport.TemplateID, detailReport.Host)
			if sqlQueryNameResult == "new" {
				log.Debug().Str("file", "main").Str("vulnerability name", detailReport.TemplateID).Str("vulnerability host", detailReport.Host).Msg("success")
				err = model.InsertSqliteVulnerability(sqlDatabase, detailReport.TemplateID, detailReport.Host, "open")
				if err != nil {
					log.Error().Stack().Err(errors.New(err.Error())).Msg("")
					return
				}
			}
			slackVulnerabilityStatus = sqlQueryNameResult
		} else if databaseType == "notion" {
			rl.Take()
			notionQueryNameResult, err := model.QueryNotionVulnerabilityName(notionDatabase, detailReport)
			if err != nil {
				log.Error().Stack().Err(errors.New(err.Error())).Msg("")
				return
			}

			if len(notionQueryNameResult) == 0 {
				rl.Take()
				_, err = model.InsertNotionVulnerability(notionDatabase, detailReport)
				if err != nil {
					log.Error().Stack().Err(errors.New(err.Error())).Msg("")
					return
				}
				slackVulnerabilityStatus = "new"
				summaryReportStatus.New++
			} else {
				notionPageList = append(notionPageList, notionQueryNameResult[0])
				slackVulnerabilityStatus = "still-open"
			}
		}
		summaryReportSeverity.Host = detailReport.Host
		// slackAttachmentList = append(slackAttachmentList, model.CreateAttachment(detailReport.Info.Name, strings.Join(detailReport.Info.Tags, ", "), detailReport.Info.Severity, detailReport.Info.Classification.CvssMetrics, strconv.FormatFloat(detailReport.Info.Classification.CvssScore, 'f', -1, 64), detailReport.Host, detailReport.Matched, slackVulnerabilityStatus))
	}

	if len(vulnerabilityList) == 0 {
		return
	}

	if databaseType == "sqlite" {
		for _, vulnerability := range vulnerabilityList {
			err = model.UpdateSqliteVulnerabilityStatus(sqlDatabase, vulnerability.TemplateID, vulnerability.Host, "open")
			if err != nil {
				log.Error().Stack().Err(errors.New(err.Error())).Msg("")
				return
			}
		}
	} else if databaseType == "notion" {
		for _, notionPage := range notionPageList {
			rl.Take()
			_, err = model.UpdateNotionVulnerabilityStatus(notionDatabase, notionPage.ID.String(), "open")
			if err != nil {
				log.Error().Stack().Err(errors.New(err.Error())).Msg("")
				return
			}
		}

		summaryReportStatus.Open = len(vulnerabilityList)
		rl.Take()
		notionQueryStatusResult, err := model.QueryNotionVulnerabilityStatus(notionDatabase, "close")
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}
		summaryReportStatus.Close = len(notionQueryStatusResult)
	}

	slackBlockList = append(slackBlockList, model.CreateBlockSummary(summaryReportSeverity, summaryReportStatus))
	err = model.SendSlackNotification(slackToken, slackAttachmentList, slackBlockList)
	if err != nil {
		log.Error().Stack().Err(errors.New(err.Error())).Msg("")
		return
	}
}
