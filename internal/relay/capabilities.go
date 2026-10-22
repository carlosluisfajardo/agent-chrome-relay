package relay

import "strings"

// The debugger shares the person's profile. Accept only reviewed, target-scoped commands.
// Storage/cookie/cache/service-worker APIs and command tunnels are deliberately unsupported;
// attaching to an owned tab does not confine those APIs to that tab's origin.
var tabCommands = func() map[string]bool {
	out := map[string]bool{}
	for _, method := range strings.Fields(`
		Runtime.enable Runtime.disable Runtime.evaluate Runtime.callFunctionOn Runtime.getProperties
		Runtime.releaseObject Runtime.releaseObjectGroup Runtime.addBinding Runtime.removeBinding Runtime.runIfWaitingForDebugger
		Page.enable Page.disable Page.navigate Page.reload Page.stopLoading Page.getFrameTree Page.getNavigationHistory
		Page.navigateToHistoryEntry Page.captureScreenshot Page.printToPDF Page.getLayoutMetrics Page.handleJavaScriptDialog
		Page.addScriptToEvaluateOnNewDocument Page.removeScriptToEvaluateOnNewDocument Page.setLifecycleEventsEnabled
		Page.setInterceptFileChooserDialog Page.setBypassCSP Page.createIsolatedWorld
		DOM.enable DOM.disable DOM.getDocument DOM.getFlattenedDocument DOM.describeNode DOM.resolveNode DOM.requestNode
		DOM.querySelector DOM.querySelectorAll DOM.getAttributes DOM.getOuterHTML DOM.getBoxModel DOM.getContentQuads
		DOM.getNodeForLocation DOM.focus DOM.scrollIntoViewIfNeeded DOM.setFileInputFiles DOM.setAttributeValue
		DOM.removeAttribute DOM.setNodeValue DOM.setOuterHTML DOM.requestChildNodes DOM.performSearch DOM.getSearchResults DOM.discardSearchResults
		Accessibility.enable Accessibility.disable Accessibility.getFullAXTree Accessibility.getPartialAXTree
		Accessibility.getRootAXNode Accessibility.getChildAXNodes Accessibility.queryAXTree
		Input.insertText Input.dispatchKeyEvent Input.dispatchMouseEvent Input.dispatchTouchEvent Input.dispatchDragEvent
		Input.setInterceptDrags Input.synthesizeScrollGesture Input.synthesizeTapGesture Input.synthesizePinchGesture
		Network.enable Network.disable Network.getResponseBody Network.getRequestPostData Network.setExtraHTTPHeaders
		Network.setCacheDisabled Network.setUserAgentOverride Network.emulateNetworkConditions Network.setBlockedURLs
		Fetch.enable Fetch.disable Fetch.continueRequest Fetch.continueResponse Fetch.continueWithAuth Fetch.failRequest
		Fetch.fulfillRequest Fetch.getResponseBody Fetch.takeResponseBodyAsStream IO.read IO.close
		CSS.enable CSS.disable CSS.getComputedStyleForNode CSS.getMatchedStylesForNode CSS.getInlineStylesForNode
		CSS.getStyleSheetText CSS.setStyleSheetText CSS.setStyleTexts CSS.forcePseudoState
		Log.enable Log.disable Inspector.enable Inspector.disable Security.enable Security.disable
		Emulation.setDeviceMetricsOverride Emulation.clearDeviceMetricsOverride Emulation.setEmulatedMedia
		Emulation.setTouchEmulationEnabled Emulation.setFocusEmulationEnabled Emulation.setTimezoneOverride
		Emulation.setLocaleOverride Emulation.setGeolocationOverride Emulation.clearGeolocationOverride
		Emulation.setUserAgentOverride Emulation.setDefaultBackgroundColorOverride Emulation.setScriptExecutionDisabled
		Target.setAutoAttach
	`) {
		out[method] = true
	}
	return out
}()
