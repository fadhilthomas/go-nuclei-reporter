package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"net/http"
	"time"
)

func CreateAttachment(name string, tags string, severity string, metric string, score string, host string, matched string, status string) (attachment SlackAttachmentBody) {
	nameField := SlackFieldBody{
		Title: "Name",
		Value: name,
		Short: false,
	}

	tagsField := SlackFieldBody{
		Title: "Tags",
		Value: fmt.Sprintf("`%s`", tags),
		Short: true,
	}

	severityField := SlackFieldBody{
		Title: "Severity",
		Value: fmt.Sprintf("`%s`", severity),
		Short: true,
	}

	metricField := SlackFieldBody{
		Title: "CVSS Metric",
		Value: fmt.Sprintf("`%s - %s`", score, metric),
		Short: false,
	}

	hostField := SlackFieldBody{
		Title: "Host",
		Value: fmt.Sprintf("`%s`", host),
		Short: true,
	}

	statusField := SlackFieldBody{
		Title: "Status",
		Value: fmt.Sprintf("`%s`", status),
		Short: true,
	}

	matchedField := SlackFieldBody{
		Title: "Endpoint",
		Value: fmt.Sprintf("`%s`", matched),
		Short: false,
	}

	var color string
	switch {
	case severity == "critical" || severity == "high":
		color = "danger"
	case severity == "medium":
		color = "warning"
	default:
		color = "good"
	}

	var fieldList []SlackFieldBody
	fieldList = append(fieldList, nameField, tagsField, severityField, metricField, hostField, statusField, matchedField)

	attachment = SlackAttachmentBody{
		Fields: fieldList,
		Color:  color,
	}
	return attachment
}

func CreateBlockSummary(severity SummaryReportSeverity, status SummaryReportStatus) (block SlackBlockBody) {
	summaryField := SlackBlockFieldBody{
		Type: "mrkdwn",
		Text: fmt.Sprintf("> *Open Vulnerability Summary*, @here\n> *Host:* `%s`\n```Severity      Count\n-------------------\nCritical      %d\nHigh          %d\nMedium        %d\nLow           %d\nInfo          %d\n-------------------\nTotal         %d```\n\n```Status      Count\n-------------------\nClose         %d\nOpen          %d\nNew           %d\n-------------------\nTotal         %d```", severity.Host, severity.Critical, severity.High, severity.Medium, severity.Low, severity.Info, severity.Critical+severity.High+severity.Medium+severity.Low+severity.Info, status.Close, status.Open, status.New, status.Open+status.Close),
	}

	block = SlackBlockBody{
		Type: "section",
		Text: summaryField,
	}
	return block
}

func SendSlackNotification(webHookURL string, attachmentList []SlackAttachmentBody, blockList []SlackBlockBody) error {
	slackMessage := SlackRequestBody{
		Title:       "Open Vulnerability",
		Text:        "Open Vulnerability",
		Attachments: attachmentList,
		Blocks:      blockList,
	}

	slackBody, err := json.Marshal(slackMessage)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, webHookURL, bytes.NewBuffer(slackBody))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req) //nolint:bodyclose
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return err
	}
	log.Debug().Str("file", "main").Msg(buf.String())
	if buf.String() != "ok" {
		return errors.New("non-ok response returned from slack")
	}
	return nil
}
