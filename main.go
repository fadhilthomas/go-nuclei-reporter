package main

import (
	"bufio"
	"encoding/json"
	"fmt"
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
	slackAttachmentList   []model.SlackAttachmentBody
	slackBlockList        []model.SlackBlockBody
	notionDatabase        *notionapi.Client
	summaryReportSeverity model.SummaryReportSeverity
	summaryReportStatus   model.SummaryReportStatus
	vulnerabilityList     []model.Vulnerability
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

	slackToken := config.GetStr(config.SLACK_TOKEN)
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
		summaryReportStatus.Close++
	}

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

		vulnerability := model.Vulnerability{}
		if detailReport.MatcherName != "" {
			vulnerability.Name = fmt.Sprintf("%s - %s", detailReport.Info.Name, detailReport.MatcherName)
		} else {
			vulnerability.Name = detailReport.Info.Name
		}
		vulnerability.Host = detailReport.Host
		vulnerability.Endpoint = detailReport.Matched
		vulnerability.Severity = detailReport.Info.Severity
		vulnerability.CVSSScore = detailReport.Info.Classification.CvssScore
		vulnerability.Tags = detailReport.Info.Tags
		vulnerabilityList = append(vulnerabilityList, vulnerability)
	}

	for _, vulnerability := range removeDuplicate(vulnerabilityList) {
		switch vulnerability.Severity {
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

		rl.Take()
		notionQueryNameResult, err := model.QueryNotionVulnerabilityName(notionDatabase, vulnerability)
		if err != nil {
			log.Error().Stack().Err(errors.New(err.Error())).Msg("")
			return
		}

		if len(notionQueryNameResult) > 0 {
			for _, notionPage := range notionQueryNameResult {
				rl.Take()
				_, err = model.UpdateNotionVulnerabilityStatus(notionDatabase, string(notionPage.ID), "open")
				if err != nil {
					log.Error().Stack().Err(errors.New(err.Error())).Msg("")
					return
				}
				summaryReportStatus.Open++
				summaryReportStatus.Close--
			}
		} else {
			rl.Take()
			_, err = model.InsertNotionVulnerability(notionDatabase, vulnerability)
			if err != nil {
				log.Error().Stack().Err(errors.New(err.Error())).Msg("")
				return
			}
			summaryReportStatus.New++
			summaryReportStatus.Open++
		}
	}

	slackBlockList = append(slackBlockList, model.CreateBlockSummary(summaryReportSeverity, summaryReportStatus))
	err = model.SendSlackNotification(slackToken, slackAttachmentList, slackBlockList)
	if err != nil {
		log.Error().Stack().Err(errors.New(err.Error())).Msg("")
		return
	}
}

func removeDuplicate(duplicate []model.Vulnerability) []model.Vulnerability {
	var unique []model.Vulnerability
	type key struct{ value1, value2 string }
	m := make(map[key]int)
	for _, v := range duplicate {
		k := key{v.Name, v.Host}
		if i, ok := m[k]; ok {
			unique[i] = v
		} else {
			m[k] = len(unique)
			unique = append(unique, v)
		}
	}
	return unique
}
