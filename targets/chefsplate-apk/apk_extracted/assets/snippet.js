window.Sprig = function() {
    S._queue.push(arguments);
};
let S = window.Sprig;
S._queue = [];

function configure(environmentId, mobileHeadersJSON) {
    S.mobileHeadersJSON = mobileHeadersJSON;
    S.config = {
        _API_URL: 'https://api.sprig.com',
        envId: environmentId,
        controllerSDKURL: 'shim.js',
        viewSDKURL: 'view.js',
    };
    const script = document.createElement('script');
    script.async = 1;
    script.src = S.config.controllerSDKURL;
    const anchor = document.getElementsByTagName('script')[0];
    anchor.parentNode.insertBefore(script, anchor);
}
function handleSurveyCallback(surveyState, callbackId) {
    if (!callbackId) {
        return Sprig.dismissActiveSurvey()
    }
    if (surveyState !== 'ready') {
        window.android_hook.surveyCallback(callbackId, surveyState, "");
    } else {
        const surveyReadyCallback = (data) => {
            window.android_hook.surveyCallback(callbackId, 'ready', JSON.stringify(data));
            Sprig.removeListener('survey.appeared', surveyReadyCallback);
        };
        Sprig('addListener', 'survey.appeared', surveyReadyCallback);
    }
}
Sprig('addListener', 'survey.willClose', (status) => {
    window.android_hook.surveyWillDismiss(JSON.stringify(status));
});
Sprig('addListener', 'visitor.id.updated', (payload) => {
    window.android_hook.visitorIdUpdated(payload.visitorId, JSON.stringify(payload));
});
Sprig('addListener', 'sdk.ready', (data) => {
    window.android_hook.sdkReady(JSON.stringify(data));
});
Sprig('addListener', 'replay.capture', (data) => {
    window.android_hook.scheduleOrCaptureReplay(JSON.stringify(data));
});
Sprig.mobileTrackEvent = async (event, userId, partnerAnonymousId, properties, callbackId) => {
    const payload = { eventName: event };
    if (userId) payload.userId = userId;
    if (partnerAnonymousId) payload.anonymousId = partnerAnonymousId;
    if (properties) payload.properties = properties;
    const result = await Sprig.identifyAndTrack(payload);
    handleSurveyCallback(result.surveyState, callbackId);
}
Sprig.mobileDisplaySurvey = async (surveyId, callbackId) => {
    const result = await Sprig.displaySurvey(surveyId);
    handleSurveyCallback(result.surveyState, callbackId);
}
Sprig.mobileIdentifyAndSetAttributes = (userId, partnerAnonymousId, attributes) => {
    const payload = { };
    if (attributes) payload.attributes = attributes;
    if (userId) payload.userId = userId;
    if (partnerAnonymousId) payload.anonymousId = partnerAnonymousId;
    Sprig('identifyAndSetAttributes', payload);
}

const eventListener = function (e) {
    window.android_hook.onSdkEvent(e.name, JSON.stringify(e));
};
Sprig.addEventListener = (event) => {
    Sprig('addListener', event, eventListener);
}

Sprig.removeEventListener = (event) => {
    Sprig('removeListener', event, eventListener);
}

// Unlike the other tracked events, question.answered doesn't include the name in the payload
Sprig('addListener', 'question.answered', (payload) => {
    window.android_hook.onSdkEvent('question.answered', JSON.stringify(payload));
});

// Replace default console functions with custom functions to push events to the WebView Controller
function createMessageJson(level, message) {
    return JSON.stringify({
        type: 'jsConsoleMessage',
        level: level,
        message: message,
    });
}

function captureConsoleLog(msg) {
    window.android_hook.postJSConsoleMessage(createMessageJson('log', msg));
}

function captureConsoleError(msg) {
    window.android_hook.postJSConsoleMessage(createMessageJson('error', msg))
}

function captureConsoleWarning(msg) {
    window.android_hook.postJSConsoleMessage(createMessageJson('warn', msg))
}

window.console.log = captureConsoleLog
window.console.error = captureConsoleError
window.console.warn = captureConsoleWarning


