package config

import (
	"fmt"
	"github.com/rs/zerolog/log"
	"os"
	"strconv"
	"time"
)

func Set(key string, value string) {
	base[key] = value
}

func GetStr(key string) string {
	value := os.Getenv(key)
	if value != "" {
		return value
	}

	value = base[key]
	if value != "" {
		return value
	}

	log.Error().Str("file", "func").Msg(fmt.Sprintf("%v is empty", key))
	os.Exit(1)

	return ""
}

func GetInt(key string) int {
	val := GetStr(key)
	if val == "" {
		log.Error().Str("file", "func").Msg(fmt.Sprintf(`config with key "%s" not found`, key))
		os.Exit(1)
	}
	valInt, err := strconv.Atoi(val)
	if err != nil {
		log.Error().Str("file", "func").Msg(fmt.Sprintf(`config with key "%s" cannot be used as int (%s)`, key, err))
		os.Exit(1)
	}
	return valInt
}

func GetDuration(key string) time.Duration {
	val := GetStr(key)
	if val == "" {
		log.Error().Str("file", "func").Msg(fmt.Sprintf(`config with key "%s" not found`, key))
		os.Exit(1)
	}
	valDuration, err := time.ParseDuration(val)
	if err != nil {
		log.Error().Str("file", "func").Msg(fmt.Sprintf(`config with key "%s" cannot be used as int (%s)`, key, err))
		os.Exit(1)
	}
	return valDuration
}

func mergeConfig(configs ...map[string]string) map[string]string {
	result := map[string]string{}

	for _, configMap := range configs {
		for key, configValue := range configMap {
			if _, ok := result[key]; ok {
				log.Error().Str("file", "func").Msg(fmt.Sprintf(`duplicate config key "%s" detected`, key))
			}
			result[key] = configValue
		}
	}

	return result
}
