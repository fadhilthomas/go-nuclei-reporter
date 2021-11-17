package config

var base = mergeConfig(
	fileLocationConfig,
	logLevelConfig,
	notionDatabaseConfig,
	notionTokenConfig,
	slackConfig,
)
