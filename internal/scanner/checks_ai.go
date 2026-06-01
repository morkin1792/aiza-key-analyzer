package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ─── AI & Machine Learning checks ────────────────────────────────────────────

func check4_37() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Gemini (Generative Language) API, letting an attacker run billable model requests on the project's account (cost abuse / model access).",
		Name: "Gemini API Abuse (Unrestricted Key)", Category: "AI", NeedsProject: false,
		PoC: `curl -s -X POST 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={KEY}' -H 'Content-Type: application/json' -d '{"contents":[{"parts":[{"text":"Say hello"}]}]}'`,
		Run: func(key, projectID string) CheckResult {
			url := "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" + key
			payload := map[string]interface{}{
				"contents": []map[string]interface{}{
					{"parts": []map[string]interface{}{
						{"text": "Say the word: hello"},
					}},
				},
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Gemini API Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Candidates []struct {
						Content struct {
							Parts []struct {
								Text string `json:"text"`
							} `json:"parts"`
						} `json:"content"`
					} `json:"candidates"`
				}
				unmarshal(body, &resp)
				detail := ""
				if len(resp.Candidates) > 0 && len(resp.Candidates[0].Content.Parts) > 0 {
					text := resp.Candidates[0].Content.Parts[0].Text
					if len(text) > 50 {
						text = text[:50] + "..."
					}
					detail = "Response: " + strings.TrimSpace(text)
				}
				return cr("Gemini API Abuse (Unrestricted Key)", "AI", StatusConfirmed, detail, body)
			}
			if code == 400 || code == 401 || code == 403 || code == 404 {
				return cr("Gemini API Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Gemini API Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

// pickGeminiModel returns the best version-less or current Gemini model name
// to use for a generateContent probe. It prefers (in order):
//  1. The "*-latest" alias when Google publishes one (survives version bumps)
//  2. Newer stable releases (gemini-2.5-flash, gemini-3.5-flash)
//  3. Any flash variant the project advertises
//  4. A hard-coded fallback when the listing endpoint is denied
//
// We probe `/v1beta/models` because hard-coding a specific version is brittle
// — Google deprecates models on roughly an 18-month cycle and the scanner
// would silently return false negatives on every key once the chosen version
// disappears.
func pickGeminiModel(escKey string) string {
	const fallback = "gemini-3.5-flash"
	u := "https://generativelanguage.googleapis.com/v1beta/models?key=" + escKey
	code, body, err := doGet(u)
	if err != nil || code != 200 {
		return fallback
	}
	var resp struct {
		Models []struct {
			Name                       string   `json:"name"`
			SupportedGenerationMethods []string `json:"supportedGenerationMethods"`
		} `json:"models"`
	}
	if unmarshal(body, &resp) != nil {
		return fallback
	}
	var available []string
	for _, m := range resp.Models {
		supports := false
		for _, method := range m.SupportedGenerationMethods {
			if method == "generateContent" {
				supports = true
				break
			}
		}
		if !supports {
			continue
		}
		available = append(available, strings.TrimPrefix(m.Name, "models/"))
	}
	preferred := []string{
		"gemini-flash-latest",
		"gemini-3.5-flash",
		"gemini-2.5-flash",
		"gemini-2.0-flash",
	}
	for _, want := range preferred {
		for _, have := range available {
			if have == want {
				return want
			}
		}
	}
	for _, have := range available {
		if strings.Contains(have, "flash") &&
			!strings.Contains(have, "exp") &&
			!strings.Contains(have, "thinking") &&
			!strings.Contains(have, "live") {
			return have
		}
	}
	if len(available) > 0 {
		return available[0]
	}
	return fallback
}

// checkGeminiGenerate confirms the key can actually invoke a Gemini model —
// elevating "Gemini Models list" from Potential to Vulnerable when it works.
// Model name is resolved at scan time via pickGeminiModel so the check
// survives Google's model-deprecation churn.
func checkGeminiGenerate() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key can invoke a live Gemini model via generateContent, letting an attacker run billable inference on the project's account (cost abuse / model access).",
		Name: "Gemini Generation Abuse (Unrestricted Key)", Category: "AI", NeedsProject: false,
		PoC: `# Lists currently-available Gemini models, then invokes the first flash variant.
MODEL=$(curl -s 'https://generativelanguage.googleapis.com/v1beta/models?key={KEY}' | jq -r '.models[] | select(.supportedGenerationMethods | index("generateContent")) | .name' | sed 's|^models/||' | grep -E 'flash' | grep -v -E 'exp|thinking|live' | head -1)
curl -s -X POST "https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent?key={KEY}" -H 'Content-Type: application/json' -d '{"contents":[{"parts":[{"text":"hi"}]}],"generationConfig":{"maxOutputTokens":1}}'`,
		Run: func(key, projectID string) CheckResult {
			model := pickGeminiModel(key)
			u := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, key)
			payload := map[string]interface{}{
				"contents": []map[string]interface{}{{
					"parts": []map[string]interface{}{{"text": "hi"}},
				}},
				"generationConfig": map[string]interface{}{"maxOutputTokens": 1},
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("Gemini Generation Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Gemini Generation Abuse (Unrestricted Key)", "AI", StatusConfirmed,
					"Gemini generateContent succeeded with model "+model+" — confirmed billing/quota abuse path", body)
			}
			if code == 400 && isInvalidKeyResponse(body) {
				return cr("Gemini Generation Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key rejected for Gemini", body)
			}
			if code == 401 || code == 403 {
				return cr("Gemini Generation Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Gemini Generation Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

// checkTranslationProbe confirms the Translation API can actually be invoked
// (each call has measurable cost), elevating Translation listing from
// Potential to Vulnerable.
func checkTranslationProbe() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Cloud Translation API, letting an attacker run billable translation requests on the project's account (cost abuse).",
		Name: "Translation API Abuse (Unrestricted Key)", Category: "AI", NeedsProject: false,
		PoC: "curl -s 'https://translation.googleapis.com/language/translate/v2?key={KEY}&q=hi&target=es'",
		Run: func(key, projectID string) CheckResult {
			u := "https://translation.googleapis.com/language/translate/v2?key=" + key + "&q=hi&target=es"
			code, body, err := doGet(u)
			if err != nil {
				return cr("Translation API Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Translation API Abuse (Unrestricted Key)", "AI", StatusConfirmed, "", body)
			}
			if code == 400 && isInvalidKeyResponse(body) {
				return cr("Translation API Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key rejected for Translation", body)
			}
			if code == 401 || code == 403 {
				return cr("Translation API Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Translation API Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

// checkVertexAIPredict invokes a Vertex AI Gemini model via the aiplatform
// endpoint — confirms the key can drive billable Vertex inference, upgrading
// the Vertex AI listing finding from Potential to Vulnerable.
//
// The Vertex publishers/google/models registry mirrors the public Gemini API
// model names, so we reuse pickGeminiModel() rather than maintaining a second
// hard-coded list that goes stale on the same schedule.
func checkVertexAIPredict() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key can drive billable Vertex AI Gemini inference on the project, letting an attacker run model requests on the project's account (cost abuse / model access).",
		Name: "Vertex AI Prediction Abuse (Unrestricted Key)", Category: "AI", NeedsProject: true,
		PoC: `# Picks the same model the scanner used by listing models on the public Gemini API
MODEL=$(curl -s 'https://generativelanguage.googleapis.com/v1beta/models?key={KEY}' | jq -r '.models[] | select(.supportedGenerationMethods | index("generateContent")) | .name' | sed 's|^models/||' | grep -E 'flash' | grep -v -E 'exp|thinking|live' | head -1)
curl -s -X POST "https://us-central1-aiplatform.googleapis.com/v1/projects/{PROJECT}/locations/us-central1/publishers/google/models/${MODEL}:generateContent?key={KEY}" -H 'Content-Type: application/json' -d '{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"generationConfig":{"maxOutputTokens":1}}'`,
		Run: func(key, projectID string) CheckResult {
			model := pickGeminiModel(key)
			u := fmt.Sprintf("https://us-central1-aiplatform.googleapis.com/v1/projects/%s/locations/us-central1/publishers/google/models/%s:generateContent?key=%s", projectID, model, key)
			payload := map[string]interface{}{
				"contents": []map[string]interface{}{{
					"role":  "user",
					"parts": []map[string]interface{}{{"text": "hi"}},
				}},
				"generationConfig": map[string]interface{}{"maxOutputTokens": 1},
			}
			code, body, err := doPost(u, payload)
			if err != nil {
				return cr("Vertex AI Prediction Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Vertex AI Prediction Abuse (Unrestricted Key)", "AI", StatusConfirmed,
					"Vertex AI generateContent succeeded with model "+model+" — confirmed billing-cost path via Vertex Gemini", body)
			}
			if code == 400 && isInvalidKeyResponse(body) {
				return cr("Vertex AI Prediction Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key rejected for Vertex AI", body)
			}
			if code == 401 || code == 403 {
				return cr("Vertex AI Prediction Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Vertex AI Prediction Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

func check4_38() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list the Gemini models available to the project, disclosing model inventory.",
		Name: "Gemini Model Enumeration", Category: "AI", NeedsProject: false,
		PoC: "curl -s 'https://generativelanguage.googleapis.com/v1beta/models?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := "https://generativelanguage.googleapis.com/v1beta/models?key=" + key
			code, body, err := doGet(url)
			if err != nil {
				return cr("Gemini Model Enumeration", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Models []struct {
						Name string `json:"name"`
					} `json:"models"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, m := range resp.Models {
					names = append(names, shortName(m.Name))
				}
				detail := fmt.Sprintf("%d models accessible", len(resp.Models))
				if len(names) > 5 {
					names = names[:5]
					detail += ": " + strings.Join(names, ", ") + ", ..."
				} else if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Gemini Model Enumeration", "AI", StatusPotential, detail+" — see Gemini Generate row for confirmed billing-abuse path", body)
			}
			if code == 401 || code == 403 {
				return cr("Gemini Model Enumeration", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Gemini Model Enumeration", "AI", code, body)
		},
	}
}

func check4_39() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Cloud Translation API, letting an attacker run billable translate requests on the project's account (cost abuse).",
		Name: "Cloud Translation Abuse (Unrestricted Key)", Category: "AI", NeedsProject: false,
		PoC: `curl -s -X POST 'https://translation.googleapis.com/language/translate/v2?key={KEY}' -H 'Content-Type: application/json' -d '{"q":"hello","target":"es","format":"text"}'`,
		Run: func(key, projectID string) CheckResult {
			url := "https://translation.googleapis.com/language/translate/v2?key=" + key
			payload := map[string]interface{}{
				"q":      "hello",
				"target": "es",
				"format": "text",
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Cloud Translation Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Cloud Translation Abuse (Unrestricted Key)", "AI", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Translation Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Translation Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

func check4_40() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Cloud Translation language-detection endpoint, letting an attacker run billable requests on the project's account (cost abuse).",
		Name: "Language Detection Abuse (Unrestricted Key)", Category: "AI", NeedsProject: false,
		PoC: `curl -s -X POST 'https://translation.googleapis.com/language/translate/v2/detect?key={KEY}' -H 'Content-Type: application/json' -d '{"q":"Hello World"}'`,
		Run: func(key, projectID string) CheckResult {
			url := "https://translation.googleapis.com/language/translate/v2/detect?key=" + key
			payload := map[string]interface{}{"q": "Hello World"}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Language Detection Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Language Detection Abuse (Unrestricted Key)", "AI", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Language Detection Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Language Detection Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

func check4_41() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Cloud Vision API, letting an attacker run billable image-analysis requests on the project's account (cost abuse).",
		Name: "Cloud Vision API Abuse (Unrestricted Key)", Category: "AI", NeedsProject: false,
		PoC: `curl -s -X POST 'https://vision.googleapis.com/v1/images:annotate?key={KEY}' -H 'Content-Type: application/json' -d '{"requests":[{"image":{"content":"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="},"features":[{"type":"LABEL_DETECTION","maxResults":1}]}]}'`,
		Run: func(key, projectID string) CheckResult {
			url := "https://vision.googleapis.com/v1/images:annotate?key=" + key
			// 1x1 white PNG base64
			payload := map[string]interface{}{
				"requests": []map[string]interface{}{
					{
						"image": map[string]interface{}{
							"content": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==",
						},
						"features": []map[string]interface{}{
							{"type": "LABEL_DETECTION", "maxResults": 1},
						},
					},
				},
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Cloud Vision API Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Cloud Vision API Abuse (Unrestricted Key)", "AI", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Vision API Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Vision API Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

func check4_42() ServiceCheck {
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Cloud Natural Language API, letting an attacker run billable NLP requests on the project's account (cost abuse).",
		Name: "Cloud Natural Language Abuse (Unrestricted Key)", Category: "AI", NeedsProject: false,
		PoC: `curl -s -X POST 'https://language.googleapis.com/v1/documents:analyzeSentiment?key={KEY}' -H 'Content-Type: application/json' -d '{"document":{"type":"PLAIN_TEXT","content":"Hello World"},"encodingType":"UTF8"}'`,
		Run: func(key, projectID string) CheckResult {
			url := "https://language.googleapis.com/v1/documents:analyzeSentiment?key=" + key
			payload := map[string]interface{}{
				"document":     map[string]interface{}{"type": "PLAIN_TEXT", "content": "Hello World"},
				"encodingType": "UTF8",
			}
			code, body, err := doPost(url, payload)
			if err != nil {
				return cr("Cloud Natural Language Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Cloud Natural Language Abuse (Unrestricted Key)", "AI", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Natural Language Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Natural Language Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

func check4_43() ServiceCheck {
	// Use a Google-public FLAC sample so we actually transcribe billable audio
	// — confirms real per-second billing impact, not just "API enabled".
	const probeBody = `{"config":{"encoding":"FLAC","sampleRateHertz":16000,"languageCode":"en-US"},"audio":{"uri":"gs://cloud-samples-tests/speech/brooklyn.flac"}}`
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Cloud Speech-to-Text API, letting an attacker run billable transcription requests on the project's account (cost abuse).",
		Name: "Cloud Speech-to-Text Abuse (Unrestricted Key)", Category: "AI", NeedsProject: false,
		PoC: `# Cloud Speech-to-Text — transcribe a real audio file (billable per second of audio)
# Variant A: use a Google-hosted public sample (no upload needed)
curl -s -X POST 'https://speech.googleapis.com/v1/speech:recognize?key={KEY}' -H 'Content-Type: application/json' -d '{"config":{"encoding":"FLAC","sampleRateHertz":16000,"languageCode":"en-US"},"audio":{"uri":"gs://cloud-samples-tests/speech/brooklyn.flac"}}'
# Variant B: transcribe your own audio (replace AUDIO_PATH with the file)
# AUDIO_B64=$(base64 -w0 < /path/to/AUDIO_PATH.flac); curl -s -X POST 'https://speech.googleapis.com/v1/speech:recognize?key={KEY}' -H 'Content-Type: application/json' -d "{\"config\":{\"encoding\":\"FLAC\",\"sampleRateHertz\":16000,\"languageCode\":\"en-US\"},\"audio\":{\"content\":\"${AUDIO_B64}\"}}"`,
		Run: func(key, projectID string) CheckResult {
			url := "https://speech.googleapis.com/v1/speech:recognize?key=" + key
			code, body, err := doPost(url, json.RawMessage(probeBody))
			if err != nil {
				return cr("Cloud Speech-to-Text Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				// Parse to see if real transcription happened.
				var resp struct {
					Results []struct {
						Alternatives []struct {
							Transcript string `json:"transcript"`
						} `json:"alternatives"`
					} `json:"results"`
				}
				unmarshal(body, &resp)
				if len(resp.Results) > 0 && len(resp.Results[0].Alternatives) > 0 {
					transcript := resp.Results[0].Alternatives[0].Transcript
					if len(transcript) > 60 {
						transcript = transcript[:60] + "..."
					}
					return cr("Cloud Speech-to-Text Abuse (Unrestricted Key)", "AI", StatusConfirmed,
						"Transcribed Google sample audio — confirmed billing (transcript: \""+transcript+"\")", body)
				}
				return cr("Cloud Speech-to-Text Abuse (Unrestricted Key)", "AI", StatusConfirmed,
					"", body)
			}
			if code == 400 {
				if isInvalidKeyResponse(body) {
					return cr("Cloud Speech-to-Text Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key rejected for this service", body)
				}
				return cr("Cloud Speech-to-Text Abuse (Unrestricted Key)", "AI", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Speech-to-Text Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Speech-to-Text Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

func check4_44() ServiceCheck {
	// We probe the actual synthesize endpoint (not /voices, which is free
	// recon). A 200 from synthesize is direct evidence of billing-cost abuse.
	const probeBody = `{"input":{"text":"aiza"},"voice":{"languageCode":"en-US","name":"en-US-Standard-A"},"audioConfig":{"audioEncoding":"MP3"}}`
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Cloud Text-to-Speech API, letting an attacker run billable synthesis requests (billed per character) on the project's account (cost abuse).",
		Name: "Cloud Text-to-Speech Abuse (Unrestricted Key)", Category: "AI", NeedsProject: false,
		PoC: `# Cloud Text-to-Speech — synthesize speech (billed per character)
curl -s -X POST 'https://texttospeech.googleapis.com/v1/text:synthesize?key={KEY}' -H 'Content-Type: application/json' -d '{"input":{"text":"This is a security demonstration."},"voice":{"languageCode":"en-US","name":"en-US-Standard-A"},"audioConfig":{"audioEncoding":"MP3"}}' | jq -r .audioContent | base64 -d > aiza_tts_poc.mp3
# The output file is real audio. Listen with: mpv aiza_tts_poc.mp3`,
		Run: func(key, projectID string) CheckResult {
			url := "https://texttospeech.googleapis.com/v1/text:synthesize?key=" + key
			code, body, err := doPost(url, json.RawMessage(probeBody))
			if err != nil {
				return cr("Cloud Text-to-Speech Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Cloud Text-to-Speech Abuse (Unrestricted Key)", "AI", StatusConfirmed,
					"", body)
			}
			if code == 401 || code == 403 {
				return cr("Cloud Text-to-Speech Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Cloud Text-to-Speech Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

func check4_45() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list deployed Vertex AI models on the project, disclosing ML model inventory (and signalling a billable inference surface).",
		Name: "Vertex AI Abuse (Unrestricted Key)", Category: "AI", NeedsProject: true,
		PoC: "curl -s 'https://us-central1-aiplatform.googleapis.com/v1/projects/{PROJECT}/locations/us-central1/models?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://us-central1-aiplatform.googleapis.com/v1/projects/%s/locations/us-central1/models?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("Vertex AI Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Models []struct {
						DisplayName string `json:"displayName"`
					} `json:"models"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, m := range resp.Models {
					names = append(names, m.DisplayName)
				}
				detail := fmt.Sprintf("%d deployed models", len(resp.Models))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Vertex AI Abuse (Unrestricted Key)", "AI", StatusPotential, detail+" — listing only; invoke a model to confirm billing-abuse path", body)
			}
			if code == 401 || code == 403 {
				return cr("Vertex AI Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Vertex AI Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

func check4_46() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list AutoML datasets on the project, exposing ML training-data inventory.",
		Name: "AutoML Abuse (Unrestricted Key)", Category: "AI", NeedsProject: true,
		PoC: "curl -s 'https://automl.googleapis.com/v1/projects/{PROJECT}/locations/us-central1/datasets?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			url := fmt.Sprintf("https://automl.googleapis.com/v1/projects/%s/locations/us-central1/datasets?key=%s", projectID, key)
			code, body, err := doGet(url)
			if err != nil {
				return cr("AutoML Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Datasets []struct {
						DisplayName string `json:"displayName"`
					} `json:"datasets"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, d := range resp.Datasets {
					names = append(names, d.DisplayName)
				}
				detail := fmt.Sprintf("%d datasets", len(resp.Datasets))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("AutoML Abuse (Unrestricted Key)", "AI", StatusPotential, detail+" — listing only", body)
			}
			if code == 401 || code == 403 {
				return cr("AutoML Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("AutoML Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

// ─── New AI & ML checks ─────────────────────────────────────────────────────

func checkGeminiTunedModels() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list fine-tuned Gemini models, disclosing custom model artifacts.",
		Name: "Gemini Tuned Model Disclosure", Category: "AI", NeedsProject: false,
		PoC: "curl -s 'https://generativelanguage.googleapis.com/v1beta/tunedModels?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := "https://generativelanguage.googleapis.com/v1beta/tunedModels?key=" + key
			code, body, err := doGet(u)
			if err != nil {
				return cr("Gemini Tuned Model Disclosure", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					TunedModels []struct {
						Name string `json:"name"`
					} `json:"tunedModels"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d tuned models", len(resp.TunedModels))
				return cr("Gemini Tuned Model Disclosure", "AI", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Gemini Tuned Model Disclosure", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Gemini Tuned Model Disclosure", "AI", code, body)
		},
	}
}

func checkVertexAIDatasets() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Vertex AI datasets, exposing ML training-data inventory.",
		Name: "Vertex AI Dataset Enumeration", Category: "AI", NeedsProject: true,
		PoC: "curl -s 'https://us-central1-aiplatform.googleapis.com/v1/projects/{PROJECT}/locations/us-central1/datasets?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://us-central1-aiplatform.googleapis.com/v1/projects/%s/locations/us-central1/datasets?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Vertex AI Dataset Enumeration", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Datasets []struct {
						DisplayName string `json:"displayName"`
					} `json:"datasets"`
				}
				unmarshal(body, &resp)
				var names []string
				for _, d := range resp.Datasets {
					names = append(names, d.DisplayName)
				}
				detail := fmt.Sprintf("%d datasets", len(resp.Datasets))
				if len(names) > 0 {
					detail += ": " + strings.Join(names, ", ")
				}
				return cr("Vertex AI Dataset Enumeration", "AI", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Vertex AI Dataset Enumeration", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Vertex AI Dataset Enumeration", "AI", code, body)
		},
	}
}

func checkGeminiFiles() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list files uploaded to the Gemini Files API, potentially exposing user-uploaded content.",
		Name: "Gemini Files API Disclosure", Category: "AI", NeedsProject: false,
		PoC: "curl -s 'https://generativelanguage.googleapis.com/v1beta/files?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := "https://generativelanguage.googleapis.com/v1beta/files?key=" + key
			code, body, err := doGet(u)
			if err != nil {
				return cr("Gemini Files API Disclosure", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Files []struct {
						Name string `json:"name"`
					} `json:"files"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d uploaded files accessible (potential data leak)", len(resp.Files))
				return cr("Gemini Files API Disclosure", "AI", StatusConfirmed, detail, body)
			}
			if code == 404 {
				return cr("Gemini Files API Disclosure", "AI", StatusError, "HTTP 404 — endpoint not found", body)
			}
			if code == 401 || code == 403 {
				return cr("Gemini Files API Disclosure", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Gemini Files API Disclosure", "AI", code, body)
		},
	}
}

func checkVideoIntelligence() ServiceCheck {
	const probeBody = `{"inputUri":"gs://cloud-samples-data/video/cat.mp4","features":["LABEL_DETECTION"]}`
	return ServiceCheck{
		Desc: "The unrestricted key is enabled for the Video Intelligence API, letting an attacker run billable video-analysis requests on the project's account (cost abuse).",
		Name: "Video Intelligence Abuse (Unrestricted Key)", Category: "AI", NeedsProject: false,
		PoC: "curl -s -X POST 'https://videointelligence.googleapis.com/v1/videos:annotate?key={KEY}' -H 'Content-Type: application/json' -d '" + probeBody + "'",
		Run: func(key, projectID string) CheckResult {
			u := "https://videointelligence.googleapis.com/v1/videos:annotate?key=" + key
			code, body, err := doPost(u, json.RawMessage(probeBody))
			if err != nil {
				return cr("Video Intelligence Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				return cr("Video Intelligence Abuse (Unrestricted Key)", "AI", StatusConfirmed, "", body)
			}
			if code == 400 {
				if isInvalidKeyResponse(body) {
					return cr("Video Intelligence Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key rejected for this service", body)
				}
				return cr("Video Intelligence Abuse (Unrestricted Key)", "AI", StatusConfirmed, "", body)
			}
			if code == 401 || code == 403 {
				return cr("Video Intelligence Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Video Intelligence Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}

func checkDocumentAI() ServiceCheck {
	return ServiceCheck{
		Desc: "The key can list Document AI processors on the project, exposing the document-processing pipeline (and a billable inference surface).",
		Name: "Document AI Abuse (Unrestricted Key)", Category: "AI", NeedsProject: true,
		PoC: "curl -s 'https://us-documentai.googleapis.com/v1/projects/{PROJECT}/locations/us/processors?key={KEY}'",
		Run: func(key, projectID string) CheckResult {
			u := fmt.Sprintf("https://us-documentai.googleapis.com/v1/projects/%s/locations/us/processors?key=%s", projectID, key)
			code, body, err := doGet(u)
			if err != nil {
				return cr("Document AI Abuse (Unrestricted Key)", "AI", StatusError, err.Error(), nil)
			}
			if code == 200 {
				var resp struct {
					Processors []struct {
						Name string `json:"name"`
					} `json:"processors"`
				}
				unmarshal(body, &resp)
				detail := fmt.Sprintf("%d Document AI processors", len(resp.Processors))
				return cr("Document AI Abuse (Unrestricted Key)", "AI", StatusConfirmed, detail, body)
			}
			if code == 401 || code == 403 {
				return cr("Document AI Abuse (Unrestricted Key)", "AI", StatusForbidden, "Key valid, API not enabled", body)
			}
			return httpError("Document AI Abuse (Unrestricted Key)", "AI", code, body)
		},
	}
}
