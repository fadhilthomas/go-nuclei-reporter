package model

import (
	"context"
	"errors"
	"fmt"
	"github.com/fadhilthomas/go-nuclei-reporter/config"
	"github.com/jomei/notionapi"
)

func OpenNotionDB() (client *notionapi.Client) {
	notionToken := config.GetStr(config.NOTION_TOKEN)
	client = notionapi.NewClient(notionapi.Token(notionToken))
	return client
}

func QueryNotionVulnerabilityName(client *notionapi.Client, vulnerability Output) (output []notionapi.Page, err error) {
	databaseId := config.GetStr(config.NOTION_DATABASE)

	var vulnerabilityName string
	if vulnerability.MatcherName != "" {
		vulnerabilityName = fmt.Sprintf("%s - %s", vulnerability.Info.Name, vulnerability.MatcherName)
	} else {
		vulnerabilityName = vulnerability.Info.Name
	}

	vulnerabilityName = truncateString(vulnerabilityName, 100)

	databaseQueryRequest := &notionapi.DatabaseQueryRequest{
		CompoundFilter: &notionapi.CompoundFilter{
			notionapi.FilterOperatorAND: []notionapi.PropertyFilter{
				{
					Property: "Name",
					Text: &notionapi.TextFilterCondition{
						Equals: vulnerabilityName,
					},
				},
				{
					Property: "Host",
					Select: &notionapi.SelectFilterCondition{
						Equals: vulnerability.Host,
					},
				},
			},
		},
	}

	res, err := client.Database.Query(context.Background(), notionapi.DatabaseID(databaseId), databaseQueryRequest)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	return res.Results, nil
}

func QueryNotionVulnerabilityStatus(client *notionapi.Client, vulnerabilityStatus string) (output []notionapi.Page, err error) {
	databaseId := config.GetStr(config.NOTION_DATABASE)
	databaseQueryRequest := &notionapi.DatabaseQueryRequest{
		PropertyFilter: &notionapi.PropertyFilter{
			Property: "Status",
			Select: &notionapi.SelectFilterCondition{
				Equals: vulnerabilityStatus,
			},
		},
	}
	res, err := client.Database.Query(context.Background(), notionapi.DatabaseID(databaseId), databaseQueryRequest)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	return res.Results, nil
}

func InsertNotionVulnerability(client *notionapi.Client, vulnerability Output) (output *notionapi.Page, err error) {
	databaseId := config.GetStr(config.NOTION_DATABASE)

	var vulnerabilityName string
	if vulnerability.MatcherName != "" {
		vulnerabilityName = fmt.Sprintf("%s - %s", vulnerability.Info.Name, vulnerability.MatcherName)
	} else {
		vulnerabilityName = vulnerability.Info.Name
	}

	vulnerabilityName = truncateString(vulnerabilityName, 100)
	vulnerabilityEndpoint := truncateString(vulnerability.Matched, 100)

	var multiSelect []notionapi.Option
	for _, tag := range vulnerability.Info.Tags {
		selectOption := notionapi.Option{
			Name: tag,
		}
		multiSelect = append(multiSelect, selectOption)
	}

	pageInsertQuery := &notionapi.PageCreateRequest{
		Parent: notionapi.Parent{
			DatabaseID: notionapi.DatabaseID(databaseId),
		},
		Properties: notionapi.Properties{
			"Name": notionapi.TitleProperty{
				Title: []notionapi.RichText{
					{
						Text: notionapi.Text{
							Content: vulnerabilityName,
						},
					},
				},
			},
			"Severity": notionapi.SelectProperty{
				Select: notionapi.Option{
					Name: vulnerability.Info.Severity,
				},
			},
			"Host": notionapi.SelectProperty{
				Select: notionapi.Option{
					Name: vulnerability.Host,
				},
			},
			"Endpoint": notionapi.RichTextProperty{
				RichText: []notionapi.RichText{
					{
						Text: notionapi.Text{
							Content: vulnerabilityEndpoint,
						},
					},
				},
			},
			"Status": notionapi.SelectProperty{
				Select: notionapi.Option{
					Name: "open",
				},
			},
			"Tags": notionapi.MultiSelectProperty{
				MultiSelect: multiSelect,
			},
			"CVSS Score": notionapi.NumberProperty{
				Number: vulnerability.Info.Classification.CvssScore,
			},
		},
	}

	res, err := client.Page.Create(context.Background(), pageInsertQuery)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	return res, nil
}

func UpdateNotionVulnerabilityStatus(client *notionapi.Client, pageId string, status string) (output *notionapi.Page, err error) {
	pageUpdateQuery := &notionapi.PageUpdateRequest{
		Properties: notionapi.Properties{
			"Status": notionapi.SelectProperty{
				Select: notionapi.Option{
					Name: status,
				},
			},
		},
	}

	res, err := client.Page.Update(context.Background(), notionapi.PageID(pageId), pageUpdateQuery)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	return res, nil
}

func truncateString(str string, num int) string {
	bnoden := str
	if len(str) > num {
		if num > 3 {
			num -= 3
		}
		bnoden = str[0:num] + "..."
	}
	return bnoden
}