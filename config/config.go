package config

var base = mergeConfig(
	logLevelConfig,
	slackConfig,
	fileLocationConfig,
	databaseLocationConfig,
)
