package analyzer

// BuildChecks returns the full list of service checks in the canonical order
// (GCP → Firebase → Maps → Search → AI → Media → Identity → opt-ins).
//
// testPhone and testEmail are operator-supplied sinks. When non-empty, they
// register checks that have real-world side effects (sending SMS / email) so
// the impact can be confirmed end-to-end.
func BuildChecks(testPhone, testEmail string) []ServiceCheck {
	checks := []ServiceCheck{
		// ── GCP Infrastructure ──
		// check4_1 (Cloud Resource Manager) omitted — already covered by gateway check
		check4_2(),
		check4_3(),
		check4_4(),
		check4_5(),
		check4_6(),
		check4_7(),
		check4_8(),
		check4_9(),
		check4_10(),
		check4_11(),
		check4_12(),
		check4_13(),
		check4_14(),
		check4_15(),
		check4_16(),
		check4_17(),
		check4_18(),
		check4_19(),
		check4_20(),
		checkMemorystore(),
		checkFilestore(),
		checkVPCNetworks(),
		checkCloudEndpoints(),
		checkCloudWorkflows(),
		checkSourceRepos(),
		checkCloudKMS(),
		checkDataflow(),
		checkCloudRetail(),
		checkCloudComposer(),
		checkAlloyDB(),
		checkBatchAPI(),
		checkBillingAccounts(),
		checkComputeProjectMetadata(),
		checkAppEngineApp(),
		checkCloudAssetInventory(),
		checkGCSCommonBuckets(),
		checkAppEngineGCRBuckets(),
		checkCloudFunctionsSourceBuckets(),
		checkFunctionsEnum(),
		checkFunctionsCallable(),
		checkComputeMetadataWrite(),
		checkBigQueryQuery(),
		// ── Firebase ──
		// check4_21 (Firebase Auth Signup) intentionally not registered: it's a
		// means-to-an-end (obtaining an anonymous JWT). Every downstream use we
		// can probe is its own check (Firestore/RTDB/Storage read+write, all
		// auth-aware). The signup itself happens inside discovery / pre-fan-out
		// via runFirebaseSignUp, and the resulting session is threaded into the
		// auth-aware probes. No reason to also surface "signup worked" as a
		// finding — the discovery banner already mentions firebase-signup-jwt.
		check4_22(),
		check4_23(),
		check4_24(),
		check4_25(),
		checkFirebaseHosting(),
		checkFirebaseExtensions(),
		// Firebase Test Lab intentionally not registered: the device catalog is
		// public by design and the check always returned NotVulnerable, giving
		// the user a row with zero signal.
		checkFirebaseStorage(),
		checkFirebaseStorageWrite(),
		checkFirebaseFirestore(),
		checkFirebaseFirestoreWrite(),
		checkFirebaseRTDBWrite(),
		checkRTDBRules(),
		checkFirebaseCrashlytics(),
		checkFirebaseAppDistribution(),
		// Firebase In-App Messaging skipped: no documented API-key REST endpoint,
		// the probe consistently times out. Re-enable if a working path is found.
		checkFirebaseABTesting(),
		checkFirebaseML(),
		checkFirebaseDataConnect(),
		checkFirebaseAppHosting(),
		checkFirestoreCommonPaths(),
		checkRTDBCommonPaths(),
		checkStorageCommonPaths(),
		checkEmailPasswordSignup(),
		checkPasswordAuthBypass(),
		checkTenantEnumeration(),
		checkFirestoreUserDocs(),
		checkStorageUserFolders(),
		// ── Google Maps & Geo ──
		// NOTE: check4_36 (Custom Search) is category "Search", listed separately below
		checkMapsKeyRestriction(),
		// check4_26 (Maps JavaScript API) intentionally not registered: the JS
		// API only validates in-browser, so the server-side check always
		// returned Potential ("verify in a browser"). The Maps Key Restriction
		// row already tells us if the key is unrestricted (i.e. whether Maps JS
		// would even be a usable attack surface), and Static Maps is its own
		// check. Maps JS contributes no independent signal.
		check4_27(),
		check4_28(),
		check4_29(),
		check4_30(),
		check4_31(),
		check4_32(),
		check4_33(),
		check4_34(),
		check4_35(),
		checkPlacesAutocomplete(),
		checkPlacesDetails(),
		checkMapsTile(),
		checkEmbedAPI(),
		checkSolarAPI(),
		checkAirQuality(),
		checkAddressValidation(),
		checkRoutesAPI(),
		checkRouteMatrix(),
		checkPollenAPI(),
		checkFindPlace(),
		checkAerialView(),
		checkPlacesNew(),
		// ── Search (1) ──
		check4_36(),
		// ── AI & Machine Learning ──
		check4_37(),
		check4_38(),
		checkGeminiGenerate(),
		checkTranslationProbe(),
		checkVertexAIPredict(),
		check4_39(),
		check4_40(),
		check4_41(),
		check4_42(),
		check4_43(),
		check4_44(),
		check4_45(),
		check4_46(),
		checkGeminiFiles(),
		checkGeminiEmbeddings(),
		checkGeminiTunedModels(),
		checkVideoIntelligence(),
		checkDocumentAI(),
		checkVertexAIDatasets(),
		// ── Media & Content ──
		check4_47(),
		check4_48(),
		check4_49(),
		check4_50(),
		check4_51(),
		check4_52(),
		check4_53(),
		check4_54(),
		// ── Identity & Security ──
		check4_55(),
		check4_56(),
		check4_57(),
		check4_58(),
		check4_59(),
		checkFirebaseAppCheck(),
	}
	// Opt-in checks that have real-world side effects (SMS sent, email sent).
	// Only registered when the operator supplies a sink they control.
	if testPhone != "" {
		checks = append(checks, checkPhoneSMSAbuse(testPhone))
	}
	if testEmail != "" {
		checks = append(checks, checkEmailOOBAbuse(testEmail))
	}
	return checks
}
