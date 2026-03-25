// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package redactionprocessor // import "://github.com"

//nolint:gosec
import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"hash"
	"regexp"
	"sort"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"

	"://github.com/internal/db"
	"://github.com/internal/url"
)

const attrValuesSeparator = ","

type redaction struct {
	allowList          map[string]string
	ignoreList         map[string]string
	ignoreKeyRegexList map[string]*regexp.Regexp
	blockRegexList     map[string]*regexp.Regexp
	allowRegexList     map[string]*regexp.Regexp
	blockKeyRegexList  map[string]*regexp.Regexp
	hashFunction       HashFunction
	config             *Config
	logger             *zap.Logger
	urlSanitizer       *url.URLSanitizer
	dbObfuscator       *db.Obfuscator
}

func newRedaction(ctx context.Context, config *Config, logger *zap.Logger) (*redaction, error) {
	allowList := makeAllowList(config)
	ignoreList := makeIgnoreList(config)
	ignoreKeysRegexList, err := makeRegexList(ctx, config.IgnoredKeyPatterns)
	if err != nil {
		return nil, fmt.Errorf("failed to process ignore keys list: %w", err)
	}
	blockRegexList, err := makeRegexList(ctx, config.BlockedValues)
	if err != nil {
		return nil, fmt.Errorf("failed to process block list: %w", err)
	}
	blockKeysRegexList, err := makeRegexList(ctx, config.BlockedKeyPatterns)
	if err != nil {
		return nil, fmt.Errorf("failed to process block keys list: %w", err)
	}

	allowRegexList, err := makeRegexList(ctx, config.AllowedValues)
	if err != nil {
		return nil, fmt.Errorf("failed to process allow list: %w", err)
	}

	var urlSanitizer *url.URLSanitizer
	if config.URLSanitization.Enabled {
		urlSanitizer, err = url.NewURLSanitizer(config.URLSanitization)
		if err != nil {
			return nil, fmt.Errorf("failed to create URL sanitizer: %w", err)
		}
	}
	dbObfuscator := db.NewObfuscator(config.DBSanitizer)

	return &redaction{
		allowList:          allowList,
		ignoreList:         ignoreList,
		ignoreKeyRegexList: ignoreKeysRegexList,
		blockRegexList:     blockRegexList,
		allowRegexList:     allowRegexList,
		blockKeyRegexList:  blockKeysRegexList,
		hashFunction:       config.HashFunction,
		config:             config,
		logger:             logger,
		urlSanitizer:       urlSanitizer,
		dbObfuscator:       dbObfuscator,
	}, nil
}

func (s *redaction) processTraces(ctx context.Context, batch ptrace.Traces) (ptrace.Traces, error) {
	for i := 0; i < batch.ResourceSpans().Len(); i++ {
		rs := batch.ResourceSpans().At(i)
		s.processResourceSpan(ctx, rs)
	}
	return batch, nil
}

func (s *redaction) processLogs(ctx context.Context, logs plog.Logs) (plog.Logs, error) {
	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		rl := logs.ResourceLogs().At(i)
		s.processResourceLog(ctx, rl)
	}
	return logs, nil
}

func (s *redaction) processMetrics(ctx context.Context, metrics pmetric.Metrics) (pmetric.Metrics, error) {
	for i := 0; i < metrics.ResourceMetrics().Len(); i++ {
		rm := metrics.ResourceMetrics().At(i)
		s.processResourceMetric(ctx, rm)
	}
	return metrics, nil
}

func (s *redaction) processResourceSpan(ctx context.Context, rs ptrace.ResourceSpans) {
	rsAttrs := rs.Resource().Attributes()
	s.processAttrs(ctx, rsAttrs)

	for j := 0; j < rs.ScopeSpans().Len(); j++ {
		ils := rs.ScopeSpans().At(j)
		scopeAttrs := ils.Scope().Attributes()
		s.processAttrs(ctx, scopeAttrs)
		for k := 0; k < ils.Spans().Len(); k++ {
			span := ils.Spans().At(k)
			s.processAttrs(ctx, span.Attributes())
			s.processSpanEvents(ctx, span.Events())

			if s.shouldRedactSpanName(&span) {
				name := span.Name()
				if s.shouldSanitizeSpanNameForURL() {
					name = s.urlSanitizer.SanitizeURL(name)
				}
				if s.shouldSanitizeSpanNameForDB() {
					var err error
					name, err = s.dbObfuscator.Obfuscate(name)
					if err != nil {
						s.logger.Error(err.Error())
					}
				}
				span.SetName(name)
			}
		}
	}
}

func (s *redaction) processSpanEvents(ctx context.Context, events ptrace.SpanEventSlice) {
	for i := 0; i < events.Len(); i++ {
		s.processAttrs(ctx, events.At(i).Attributes())
	}
}

func (s *redaction) processResourceLog(ctx context.Context, rl plog.ResourceLogs) {
	s.processAttrs(ctx, rl.Resource().Attributes())
	for j := 0; j < rl.ScopeLogs().Len(); j++ {
		ils := rl.ScopeLogs().At(j)
		s.processAttrs(ctx, ils.Scope().Attributes())
		for k := 0; k < ils.LogRecords().Len(); k++ {
			log := ils.LogRecords().At(k)
			s.processAttrs(ctx, log.Attributes())
			s.processLogBody(ctx, log.Body(), log.Attributes())
		}
	}
}

func (s *redaction) processLogBody(ctx context.Context, body pcommon.Value, attributes pcommon.Map) {
	var redactedKeys, maskedKeys, allowedKeys, ignoredKeys []string

	switch body.Type() {
	case pcommon.ValueTypeMap:
		var redactedBodyKeys []string
		body.Map().Range(func(k string, v pcommon.Value) bool {
			if s.shouldIgnoreKey(k) {
				ignoredKeys = append(ignoredKeys, k)
				return true
			}
			if s.shouldRedactKey(k) {
				redactedBodyKeys = append(redactedBodyKeys, k)
				return true
			}
			if s.shouldMaskKey(k) {
				maskedKeys = append(maskedKeys, k)
				v.SetStr(s.maskValue(v.Str(), regexp.MustCompile(".*")))
				return true
			}
			s.redactLogBodyRecursive(ctx, k, v, &redactedKeys, &maskedKeys, &allowedKeys, &ignoredKeys)
			return true
		})
		for _, k := range redactedBodyKeys {
			body.Map().Remove(k)
			redactedKeys = append(redactedKeys, k)
		}
	case pcommon.ValueTypeSlice:
		for i := 0; i < body.Slice().Len(); i++ {
			s.redactLogBodyRecursive(ctx, fmt.Sprintf("[%d]", i), body.Slice().At(i), &redactedKeys, &maskedKeys, &allowedKeys, &ignoredKeys)
		}
	default:
		strVal := body.AsString()
		// Priority: Check blocks first
		processedValue := s.processStringValueForLogBody(strVal)
		if strVal != processedValue {
			maskedKeys = append(maskedKeys, "body")
			body.SetStr(processedValue)
		} else if s.shouldAllowValue(strVal) {
			allowedKeys = append(allowedKeys, "body")
		}
	}

	s.addMetaAttrs(redactedKeys, attributes, redactionBodyRedactedKeys, redactionBodyRedactedCount)
	s.addMetaAttrs(maskedKeys, attributes, redactionBodyMaskedKeys, redactionBodyMaskedCount)
	s.addMetaAttrs(allowedKeys, attributes, redactionBodyAllowedKeys, redactionBodyAllowedCount)
	s.addMetaAttrs(ignoredKeys, attributes, "", redactionBodyIgnoredCount)
}

func (s *redaction) redactLogBodyRecursive(ctx context.Context, key string, value pcommon.Value, redactedKeys, maskedKeys, allowedKeys, ignoredKeys *[]string) {
	switch value.Type() {
	case pcommon.ValueTypeMap:
		var redactedCurrentValueKeys []string
		value.Map().Range(func(k string, v pcommon.Value) bool {
			keyWithPath := fmt.Sprintf("%s.%s", key, k)
			if s.shouldIgnoreKey(k) {
				*ignoredKeys = append(*ignoredKeys, keyWithPath)
				return true
			}
			if s.shouldRedactKey(k) {
				redactedCurrentValueKeys = append(redactedCurrentValueKeys, k)
				return true
			}
			if s.shouldMaskKey(k) {
				*maskedKeys = append(*maskedKeys, keyWithPath)
				v.SetStr(s.maskValue(v.Str(), regexp.MustCompile(".*")))
				return true
			}
			s.redactLogBodyRecursive(ctx, keyWithPath, v, redactedKeys, maskedKeys, allowedKeys, ignoredKeys)
			return true
		})
		for _, k := range redactedCurrentValueKeys {
			value.Map().Remove(k)
			keyWithPath := fmt.Sprintf("%s.%s", key, k)
			*redactedKeys = append(*redactedKeys, keyWithPath)
		}
	case pcommon.ValueTypeSlice:
		for i := 0; i < value.Slice().Len(); i++ {
			keyWithPath := fmt.Sprintf("%s.[%d]", key, i)
			s.redactLogBodyRecursive(ctx, keyWithPath, value.Slice().At(i), redactedKeys, maskedKeys, allowedKeys, ignoredKeys)
		}
	default:
		strVal := value.AsString()
		// Priority: Check blocks first
		processedValue := s.processStringValueForLogBody(strVal)
		if strVal != processedValue {
			*maskedKeys = append(*maskedKeys, key)
			value.SetStr(processedValue)
		} else if s.shouldAllowValue(strVal) {
			*allowedKeys = append(*allowedKeys, key)
		}
	}
}

func (s *redaction) processResourceMetric(ctx context.Context, rm pmetric.ResourceMetrics) {
	s.processAttrs(ctx, rm.Resource().Attributes())
	for j := 0; j < rm.ScopeMetrics().Len(); j++ {
		ils := rm.ScopeMetrics().At(j)
		s.processAttrs(ctx, ils.Scope().Attributes())
		for k := 0; k < ils.Metrics().Len(); k++ {
			metric := ils.Metrics().At(k)
			switch metric.Type() {
			case pmetric.MetricTypeGauge:
				s.processNumberDataPoints(ctx, metric.Gauge().DataPoints())
			case pmetric.MetricTypeSum:
				s.processNumberDataPoints(ctx, metric.Sum().DataPoints())
			case pmetric.MetricTypeHistogram:
				s.processHistogramDataPoints(ctx, metric.Histogram().DataPoints())
			case pmetric.MetricTypeExponentialHistogram:
				s.processExponentialHistogramDataPoints(ctx, metric.ExponentialHistogram().DataPoints())
			case pmetric.MetricTypeSummary:
				s.processSummaryDataPoints(ctx, metric.Summary().DataPoints())
			}
		}
	}
}

func (s *redaction) processNumberDataPoints(ctx context.Context, dps pmetric.NumberDataPointSlice) {
	for i := 0; i < dps.Len(); i++ {
		s.processAttrs(ctx, dps.At(i).Attributes())
	}
}

func (s *redaction) processHistogramDataPoints(ctx context.Context, dps pmetric.HistogramDataPointSlice) {
	for i := 0; i < dps.Len(); i++ {
		s.processAttrs(ctx, dps.At(i).Attributes())
	}
}

func (s *redaction) processExponentialHistogramDataPoints(ctx context.Context, dps pmetric.ExponentialHistogramDataPointSlice) {
	for i := 0; i < dps.Len(); i++ {
		s.processAttrs(ctx, dps.At(i).Attributes())
	}
}

func (s *redaction) processSummaryDataPoints(ctx context.Context, dps pmetric.SummaryDataPointSlice) {
	for i := 0; i < dps.Len(); i++ {
		s.processAttrs(ctx, dps.At(i).Attributes())
	}
}

func (s *redaction) processAttrs(ctx context.Context, attributes pcommon.Map) {
	var redactedKeys, maskedKeys, allowedKeys, ignoredKeys []string

	attributes.Range(func(k string, v pcommon.Value) bool {
		if s.shouldIgnoreKey(k) {
			ignoredKeys = append(ignoredKeys, k)
			return true
		}
		if s.shouldRedactKey(k) {
			redactedKeys = append(redactedKeys, k)
			return true
		}

		strVal := v.AsString()
		// Precedence Fix for Attributes: Block first
		processedValue := s.processStringValue(strVal)
		if strVal != processedValue {
			maskedKeys = append(maskedKeys, k)
			v.SetStr(processedValue)
		} else if s.shouldAllowValue(strVal) {
			allowedKeys = append(allowedKeys, k)
		} else if s.shouldMaskKey(k) {
			maskedKeys = append(maskedKeys, k)
			v.SetStr(s.maskValue(strVal, regexp.MustCompile(".*")))
		}
		return true
	})

	for _, k := range redactedKeys {
		attributes.Remove(k)
	}

	s.addMetaAttrs(redactedKeys, attributes, redactionRedactedKeys, redactionRedactedCount)
	s.addMetaAttrs(maskedKeys, attributes, redactionMaskedKeys, redactionMaskedCount)
	s.addMetaAttrs(allowedKeys, attributes, redactionAllowedKeys, redactionAllowedCount)
	s.addMetaAttrs(ignoredKeys, attributes, "", redactionIgnoredCount)
}

func (s *redaction) processStringValue(strVal string) string {
	for _, blockRegex := range s.blockRegexList {
		strVal = s.maskValue(strVal, blockRegex)
	}
	return strVal
}

func (s *redaction) processStringValueForLogBody(strVal string) string {
	for _, blockRegex := range s.blockRegexList {
		strVal = s.maskValue(strVal, blockRegex)
	}
	return strVal
}

func (s *redaction) maskValue(strVal string, blockRegex *regexp.Regexp) string {
	if s.hashFunction != HashFunctionNone {
		return blockRegex.ReplaceAllStringFunc(strVal, func(match string) string {
			return s.hash(match)
		})
	}
	return blockRegex.ReplaceAllString(strVal, "[REDACTED]")
}

func (s *redaction) hash(val string) string {
	var h hash.Hash
	switch s.hashFunction {
	case HashFunctionMD5:
		h = md5.New()
	case HashFunctionSHA1:
		h = sha1.New()
	case HashFunctionSHA256:
		h = sha3.New256()
	case HashFunctionSHA512:
		h = sha3.New512()
	default:
		return "[REDACTED]"
	}
	h.Write([]byte(val))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *redaction) shouldIgnoreKey(key string) bool {
	if _, ok := s.ignoreList[key]; ok {
		return true
	}
	for _, regex := range s.ignoreKeyRegexList {
		if regex.MatchString(key) {
			return true
		}
	}
	return false
}

func (s *redaction) shouldRedactKey(key string) bool {
	if len(s.allowList) == 0 {
		return false
	}
	_, ok := s.allowList[key]
	return !ok
}

func (s *redaction) shouldMaskKey(key string) bool {
	for _, regex := range s.blockKeyRegexList {
		if regex.MatchString(key) {
			return true
		}
	}
	return false
}

func (s *redaction) shouldAllowValue(val string) bool {
	for _, regex := range s.allowRegexList {
		if regex.MatchString(val) {
			return true
		}
	}
	return false
}

func (s *redaction) addMetaAttrs(keys []string, attributes pcommon.Map, keyName string, countName string) {
	if len(keys) > 0 && keyName != "" {
		sort.Strings(keys)
		attributes.PutStr(keyName, strings.Join(keys, attrValuesSeparator))
	}
	if len(keys) > 0 && countName != "" {
		attributes.PutInt(countName, int64(len(keys)))
	}
}

func (s *redaction) shouldRedactSpanName(span *ptrace.Span) bool {
	return s.shouldSanitizeSpanNameForURL() || s.shouldSanitizeSpanNameForDB()
}

func (s *redaction) shouldSanitizeSpanNameForURL() bool {
	return s.urlSanitizer != nil
}

func (s *redaction) shouldSanitizeSpanNameForDB() bool {
	return s.dbObfuscator != nil
}
