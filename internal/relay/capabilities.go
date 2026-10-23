package relay

import (
	"encoding/json"
	"strings"
)

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
		Network.enable Network.disable Network.getResponseBody Network.getRequestPostData
		Network.setCacheDisabled Network.setUserAgentOverride Network.emulateNetworkConditions Network.setBlockedURLs
		IO.read IO.close
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

// Network monitoring is useful for navigation and loading status, but Chrome's
// protocol also exposes HttpOnly cookies and raw headers. Project reviewed fields
// instead of forwarding a growing protocol object minus a few known secret keys.
// Fetch interception is unsupported: its response overrides can write cookies.
func networkFields(p map[string]any, names string) map[string]any {
	out := map[string]any{}
	for _, name := range strings.Fields(names) {
		switch v := p[name].(type) {
		case string, float64, bool:
			out[name] = v
		}
	}
	return out
}

func networkObject(p map[string]any, name string) map[string]any {
	o, _ := p[name].(map[string]any)
	return o
}

func networkResponse(p map[string]any) map[string]any {
	out := networkFields(p, "url status statusText mimeType charset connectionReused connectionId remoteIPAddress remotePort fromDiskCache fromServiceWorker fromPrefetchCache encodedDataLength protocol securityState responseTime")
	out["headers"] = map[string]any{}
	return out
}

func networkEvent(method string, p map[string]any) (map[string]any, bool) {
	var out map[string]any
	switch method {
	case "Network.requestWillBeSent":
		out = networkFields(p, "requestId loaderId documentURL timestamp wallTime type frameId hasUserGesture")
		r := networkFields(networkObject(p, "request"), "url urlFragment method postData hasPostData mixedContentType initialPriority referrerPolicy isLinkPreload")
		r["headers"] = map[string]any{}
		out["request"] = r
		out["initiator"] = networkFields(networkObject(p, "initiator"), "type url lineNumber columnNumber")
		if r := networkObject(p, "redirectResponse"); r != nil {
			out["redirectResponse"] = networkResponse(r)
		}
		out["redirectHasExtraInfo"] = false // clients must not wait for withheld cookie events
	case "Network.responseReceived":
		out = networkFields(p, "requestId loaderId timestamp type frameId")
		out["response"] = networkResponse(networkObject(p, "response"))
		out["hasExtraInfo"] = false
	case "Network.webSocketWillSendHandshakeRequest":
		out = networkFields(p, "requestId timestamp wallTime")
		out["request"] = map[string]any{"headers": map[string]any{}}
	case "Network.webSocketHandshakeResponseReceived":
		out = networkFields(p, "requestId timestamp")
		out["response"] = networkResponse(networkObject(p, "response"))
	case "Network.webSocketFrameReceived", "Network.webSocketFrameSent":
		out = networkFields(p, "requestId timestamp")
		out["response"] = networkFields(networkObject(p, "response"), "opcode mask payloadData")
	case "Network.loadingFinished":
		out = networkFields(p, "requestId timestamp encodedDataLength")
	case "Network.loadingFailed":
		out = networkFields(p, "requestId timestamp type errorText canceled blockedReason")
	case "Network.dataReceived":
		out = networkFields(p, "requestId timestamp dataLength encodedDataLength data")
	case "Network.requestServedFromCache":
		out = networkFields(p, "requestId")
	case "Network.resourceChangedPriority":
		out = networkFields(p, "requestId newPriority timestamp")
	case "Network.webSocketCreated":
		out = networkFields(p, "requestId url")
	case "Network.webSocketClosed":
		out = networkFields(p, "requestId timestamp")
	case "Network.webSocketFrameError":
		out = networkFields(p, "requestId timestamp errorMessage")
	case "Network.eventSourceMessageReceived":
		out = networkFields(p, "requestId timestamp eventName eventId data")
	default:
		return nil, false // ExtraInfo, early hints, signed exchanges and unknown events are not capabilities
	}
	return out, true
}

func networkResult(method string, raw json.RawMessage) json.RawMessage {
	var p map[string]any
	json.Unmarshal(raw, &p)
	fields := ""
	switch method {
	case "Network.getResponseBody":
		fields = "body base64Encoded"
	case "Network.getRequestPostData":
		fields = "postData"
	}
	b, _ := json.Marshal(networkFields(p, fields))
	return b
}
