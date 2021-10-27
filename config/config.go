package config

var base = mergeConfig(
	databaseLocationConfig,
	databaseTypeConfig,
	fileLocationConfig,
	logLevelConfig,
	notionDatabaseConfig,
	notionTokenConfig,
	slackConfig,
)
