var B64 = {
    alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
    lookup: null,
    ie: /MSIE /.test(navigator.userAgent),
    ieo: /MSIE [67]/.test(navigator.userAgent),
    encode: function (s) {
        var buffer = B64.toUtf8(s),
            position = -1,
            len = buffer.length,
            nan0, nan1, nan2, enc = [, , , ];
        if (B64.ie) {
            var result = [];
            while (++position < len) {
                nan0 = buffer[position];
                nan1 = buffer[++position];
                enc[0] = nan0 >> 2;
                enc[1] = ((nan0 & 3) << 4) | (nan1 >> 4);
                if (isNaN(nan1))
                    enc[2] = enc[3] = 64;
                else {
                    nan2 = buffer[++position];
                    enc[2] = ((nan1 & 15) << 2) | (nan2 >> 6);
                    enc[3] = (isNaN(nan2)) ? 64 : nan2 & 63;
                }
                result.push(B64.alphabet.charAt(enc[0]), B64.alphabet.charAt(enc[1]), B64.alphabet.charAt(enc[2]), B64.alphabet.charAt(enc[3]));
            }
            return result.join('');
        } else {
            var result = '';
            while (++position < len) {
                nan0 = buffer[position];
                nan1 = buffer[++position];
                enc[0] = nan0 >> 2;
                enc[1] = ((nan0 & 3) << 4) | (nan1 >> 4);
                if (isNaN(nan1))
                    enc[2] = enc[3] = 64;
                else {
                    nan2 = buffer[++position];
                    enc[2] = ((nan1 & 15) << 2) | (nan2 >> 6);
                    enc[3] = (isNaN(nan2)) ? 64 : nan2 & 63;
                }
                result += B64.alphabet[enc[0]] + B64.alphabet[enc[1]] + B64.alphabet[enc[2]] + B64.alphabet[enc[3]];
            }
            return result;
        }
    },
    decode: function (s) {
        if (s.length % 4)
            throw new Error("InvalidCharacterError: 'B64.decode' failed: The string to be decoded is not correctly encoded.");
        var buffer = B64.fromUtf8(s),
            position = 0,
            len = buffer.length;
        if (B64.ieo) {
            var result = [];
            while (position < len) {
                if (buffer[position] < 128) 
                    result.push(String.fromCharCode(buffer[position++]));
                else if (buffer[position] > 191 && buffer[position] < 224) 
                    result.push(String.fromCharCode(((buffer[position++] & 31) << 6) | (buffer[position++] & 63)));
                else 
                    result.push(String.fromCharCode(((buffer[position++] & 15) << 12) | ((buffer[position++] & 63) << 6) | (buffer[position++] & 63)));
            }
            return result.join('');
        } else {
            var result = '';
            while (position < len) {
                if (buffer[position] < 128) 
                    result += String.fromCharCode(buffer[position++]);
                else if (buffer[position] > 191 && buffer[position] < 224) 
                    result += String.fromCharCode(((buffer[position++] & 31) << 6) | (buffer[position++] & 63));
                else 
                    result += String.fromCharCode(((buffer[position++] & 15) << 12) | ((buffer[position++] & 63) << 6) | (buffer[position++] & 63));
            }
            return result;
        }
    },
    toUtf8: function (s) {
        var position = -1,
            len = s.length,
            chr, buffer = [];
        if (/^[\x00-\x7f]*$/.test(s)) while (++position < len)
            buffer.push(s.charCodeAt(position));
        else while (++position < len) {
            chr = s.charCodeAt(position);
            if (chr < 128) 
                buffer.push(chr);
            else if (chr < 2048) 
                buffer.push((chr >> 6) | 192, (chr & 63) | 128);
            else 
                buffer.push((chr >> 12) | 224, ((chr >> 6) & 63) | 128, (chr & 63) | 128);
        }
        return buffer;
    },
    fromUtf8: function (s) {
        var position = -1,
            len, buffer = [],
            enc = [, , , ];
        if (!B64.lookup) {
            len = B64.alphabet.length;
            B64.lookup = {};
            while (++position < len)
                B64.lookup[B64.alphabet.charAt(position)] = position;
            position = -1;
        }
        len = s.length;
        while (++position < len) {
            enc[0] = B64.lookup[s.charAt(position)];
            enc[1] = B64.lookup[s.charAt(++position)];
            buffer.push((enc[0] << 2) | (enc[1] >> 4));
            enc[2] = B64.lookup[s.charAt(++position)];
            if (enc[2] == 64) 
                break;
            buffer.push(((enc[1] & 15) << 4) | (enc[2] >> 2));
            enc[3] = B64.lookup[s.charAt(++position)];
            if (enc[3] == 64) 
                break;
            buffer.push(((enc[2] & 3) << 6) | enc[3]);
        }
        return buffer;
    }
};

if (!Date.prototype.toISOString) {
    Date.prototype.toISOString = function () {
        function pad(n) { return n < 10 ? '0' + n : n; }
        function ms(n) { return n < 10 ? '00'+ n : n < 100 ? '0' + n : n }
        return this.getFullYear() + '-' +
            pad(this.getMonth() + 1) + '-' +
            pad(this.getDate()) + 'T' +
            pad(this.getHours()) + ':' +
            pad(this.getMinutes()) + ':' +
            pad(this.getSeconds()) + '.' +
            ms(this.getMilliseconds()) + 'Z';
    }
}

function createHAR(address, title, startTime, resources, domTree, allCookies)
{
    var entries = [];
    var entryCount = 0;
    resources.forEach(function (resource) {
        var request = resource.request,
            startReply = resource.startReply,
            endReply = resource.endReply;

        if (!request || !startReply || !endReply) {
            return;
        }

        // Exclude Data URI from HAR file because
        // they aren't included in specification
        if (request.url.match(/(^data:image\/.*)/i)) {
            return;
        }

        if (entryCount == 0)
        {
                entries.push({
                startedDateTime: request.time.toISOString(),
                time: endReply.time - request.time,
                request: {
                    method: request.method,
                    url: request.url,
                    httpVersion: "HTTP/1.1",
                    cookies: [],
                    headers: request.headers,
                    queryString: [],
                    headersSize: -1,
                    bodySize: -1
                },
                response: {
                    status: endReply.status,
                    statusText: endReply.statusText,
                    httpVersion: "HTTP/1.1",
                    cookies: [
                        allCookies
                    ],
                    headers: endReply.headers,
                    redirectURL: "",
                    headersSize: -1,
                    bodySize: startReply.bodySize,
                    content: {
                        size: startReply.bodySize,
                        mimeType: endReply.contentType,
                        text: B64.encode(domTree)
                    }
                },
                cache: {},
                timings: {
                    blocked: 0,
                    dns: -1,
                    connect: -1,
                    send: 0,
                    wait: startReply.time - request.time,
                    receive: endReply.time - startReply.time,
                    ssl: -1
                },
                pageref: address
            });    
        }
        else 
        {
            entries.push({
                startedDateTime: request.time.toISOString(),
                time: endReply.time - request.time,
                request: {
                    method: request.method,
                    url: request.url,
                    httpVersion: "HTTP/1.1",
                    cookies: [],
                    headers: request.headers,
                    queryString: [],
                    headersSize: -1,
                    bodySize: -1
                },
                response: {
                    status: endReply.status,
                    statusText: endReply.statusText,
                    httpVersion: "HTTP/1.1",
                    cookies: [],
                    headers: endReply.headers,
                    redirectURL: "",
                    headersSize: -1,
                    bodySize: startReply.bodySize,
                    content: {
                        size: startReply.bodySize,
                        mimeType: endReply.contentType
                    }
                },
                cache: {},
                timings: {
                    blocked: 0,
                    dns: -1,
                    connect: -1,
                    send: 0,
                    wait: startReply.time - request.time,
                    receive: endReply.time - startReply.time,
                    ssl: -1
                },
                pageref: address
            });
        }
        entryCount = entryCount + 1;
    });

    return {
        log: {
            version: '1.2',
            creator: {
                name: "PhantomJS",
                version: phantom.version.major + '.' + phantom.version.minor +
                    '.' + phantom.version.patch
            },
            pages: [{
                startedDateTime: startTime.toISOString(),
                id: address,
                title: title,
                pageTimings: {
                    onLoad: page.endTime - page.startTime
                }
            }],
            entries: entries
        }
    };
}

var debug = {
	time: new Date(),
	loadTime: null,
	processingTime: null,
	requests: [],
	stripped: [],
	cssLength: 0
};

var fs = require("fs");
var webpage = require("webpage");
var system = require("system");

phantom.onError = function (msg, trace) {
	outputError("PHANTOM ERROR", msg, trace);
};

var args = [].slice.call(system.args, 1), arg;
var html, url, fakeUrl;
var value;
var width = 1200;
var height = 0;
var matchMQ;
var allowCrossDomain;
var required;
var prefetch;
var cssOnly = false;
var cssId;
var cssToken;
var exposeStylesheets;
var stripResources;
var localStorage;
var outputDebug;

while (args.length) {
	arg = args.shift();
	switch (arg) {

		case "-f":
		case "--fake-url":
			value = (args.length) ? args.shift() : "";
			if (value) {
				if (!value.match(/(\/|\.[^./]+)$/)) {
					value += "/";
				}
				fakeUrl = value;
			}
			else {
				fail("Expected string for '--fake-url' option");
			}
			break;

		case "-w":
		case "--width":
			value = (args.length) ? args.shift() : "";
			if (value.match(/^\d+$/)) {
				width = value;
			}
			else {
				fail("Expected numeric value for '--width' option");
			}
			break;

		case "-h":
		case "--height":
			value = (args.length) ? args.shift() : "";
			if (value.match(/^\d+$/)) {
				height = value;
			}
			else {
				fail("Expected numeric value for '--height' option");
			}
			break;

		case "-m":
		case "--match-media-queries":
			matchMQ = true;
			break;

		case "-x":
		case "--allow-cross-domain":
			allowCrossDomain = true;
			break;

		case "-r":
		case "--required-selectors":
			value = (args.length) ? args.shift() : "";
			if (value) {
				value = parseString(value);
				if (typeof value == "string") {
					value = value.split(/\s*,\s*/).map(function (string) {
						return "(?:" + string.replace(/([.*+?=^!:${}()|[\]\/\\])/g, '\\$1') + ")";
					}).join("|");

					value = [value];
				}

				required = value;
			}
			else {
				fail("Expected a string for '--required-selectors' option");
			}
			break;

		case "-e":
		case "--expose-stylesheets":
			value = (args.length) ? args.shift() : "";
			if (value) {
				exposeStylesheets = ((value.indexOf(".") > -1) ? "" : "var ") + value;
			}
			else {
				fail("Expected a string for '--expose-stylesheets' option");
			}
			break;

		case "-p":
		case "--prefetch":
			prefetch = true;
			break;

		case "-t":
		case "--insertion-token":
			value = (args.length) ? args.shift() : "";
			if (value) {
				cssToken = parseString(value);
			}
			else {
				fail("Expected a string for '--insertion-token' option");
			}
			break;

		case "-i":
		case "--css-id":
			value = (args.length) ? args.shift() : "";
			if (value) {
				cssId = value;
			}
			else {
				fail("Expected a string for '--css-id' option");
			}
			break;

		case "-s":
		case "--strip-resources":
			value = (args.length) ? args.shift() : "";
			if (value) {
				value = parseString(value);
				if (typeof value == "string") {
					value = [value];
				}
				value = value.map(function (string) {
					//throw new Error(string);
					return new RegExp(string, "i");
				});
				stripResources = value;
			}
			else {
				fail("Expected a string for '--strip-resources' option");
			}
			break;

		case "-l":
		case "--local-storage":
			value = (args.length) ? args.shift() : "";
			if (value) {
				localStorage = parseString(value);
			}
			else {
				fail("Expected a string for '--local-storage' option");
			}
			break;

		case "-c":
		case "--css-only":
			cssOnly = true;
			break;

		case "-d":
		case "--debug":
			outputDebug = true;
			break;

		case "-isM":
		case "--isMobile":
			value = (args.length) ? args.shift() : "";
			isMobile = value;
			break;
		default:
			if (!url && !arg.match(/^--?[a-z]/)) {
				url = arg;
			}
			else {
				fail("Unknown option");
			}
			break;
	}

}

var page = webpage.create();
page.resources = [];

if (page.isMobile == 'true') {
    page.settings.userAgent = "Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30";
}
else {
    page.settings.userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5";
};

if ( allowCrossDomain ) {
	page.settings.webSecurityEnabled = false;
}

page.viewportSize = {
	width: width,
	height: height || 800
};

page.onLoadStarted = function () {
    page.startTime = new Date();
};

var baseUrl = url || fakeUrl;
page.onResourceRequested = function (requestData, request) {
		var _url = requestData.url;
		if (_url.indexOf(baseUrl) > -1) {
			_url = _url.slice(baseUrl.length);
		}
		if (!_url.match(/^data/) && debug.requests.indexOf(_url) < 0) {
			debug.requests.push(_url);
		}
		var i = 0;
		var l = 0;
		if (stripResources) {
			l = stripResources.length;
			// /http:\/\/.+?\.(jpg|png|svg|gif)$/gi
			while (i < l) {
				if (stripResources[i++].test(_url)) {
					debug.stripped.push(_url);
					request.abort();
					break;
				}
			}
		}
		page.resources[requestData.id] = {
	    request: requestData,
	    startReply: null,
	    endReply: null
    };
};


page.onResourceReceived = function (res) {
	if (res.stage === 'start') {
        page.resources[res.id].startReply = res;
    }
    if (res.stage === 'end') {
        page.resources[res.id].endReply = res;
    }
};


page.onCallback = function (response) {
	page.close();
	var har;
	var allCookies = phantom.cookies;
	if ("css" in response) {
		var result;
		if (cssOnly) {
			result = response.css;
		}
		else {
			result = inlineCSS(response.css);
		}
		if (outputDebug) {
			debug.cssLength = response.css.length;
			debug.time = new Date() - debug.time;
			debug.processingTime = debug.time - debug.loadTime;
			result += "\n<!--\n\t" + JSON.stringify(debug) + "\n-->";
		}
		har = createHAR(page.address, page.title, page.startTime, page.resources, result, allCookies);
		system.stdout.write(JSON.stringify(har, undefined, 4));
//		system.stdout.write(result);
//		system.stdout.write(har);
		phantom.exit();
	}
	else {
		har = createHAR(page.address, page.title, page.startTime, page.resources, null, allCookies);
		system.stdout.write(JSON.stringify(har, undefined, 4));
		phantom.exit();
	}
};

page.onError = function (msg, trace) {
	outputError("PHANTOM PAGE ERROR", msg, trace);
};

page.onLoadFinished = function () {

	if (!html) {
		html = page.evaluate(function () {
			var xhr = new XMLHttpRequest();
			var html;
			xhr.open("get", window.location.href, false);
			xhr.onload = function () {
				html = xhr.responseText;
			};
			xhr.send();
			return html;
			// return document.documentElement.innerHTML
		});
	}

	debug.loadTime = new Date() - debug.loadTime;

	var options = {};

	if (matchMQ) {
		options.matchMQ = true;
	}

	if (allowCrossDomain) {
		options.allowCrossDomain = true;
	}

	if (required) {
		options.required = required;
	}

	if (localStorage) {
		page.evaluate(function (data) {
			var storage = window.localStorage;
			if (storage) {
				for (var key in data) {
					storage.setItem(key, data[key]);
				}
			}
		}, localStorage);
	}

	if (Object.keys(options).length) {
		page.evaluate(function (options) {
			window.extractCSSOptions = options;
		}, options);
	}

	if (!height) {
		var _height = page.evaluate(function () {
			return document.body.offsetHeight;
		});
		page.viewportSize = {
			width: width,
			height: _height
		};
	}

	var scriptPath = "/extractCSS.js";

	if (fs.isLink(system.args[0])) {
		scriptPath = fs.readLink(system.args[0]).replace(/\/[\/]+$/, "");
	}
	else {
		scriptPath = phantom.libraryPath + scriptPath;
	}

	if (!fs.isFile(scriptPath)) {
		fail("Unable to locate script at: " + scriptPath);
	}

	var injection = page.injectJs(scriptPath);
	if (!injection) {
		fail("Unable to inject script in page");
	}

};

if (url) {

	debug.loadTime = new Date();
	page.open(url);

}
else {

	if (!fakeUrl) {
		fail("Missing \"fake-url\" option");
	}

	html = system.stdin.read();
	system.stdin.close();

	debug.loadTime = new Date();
	page.setContent(html, fakeUrl);

}



function inlineCSS(css) {

	if (!css) {
		return html;
	}

	var tokenAtFirstStylesheet = !cssToken; // auto-insert css if no cssToken has been specified.
	var insertToken = function (m) {
			var string = "";
			if (tokenAtFirstStylesheet) {
				tokenAtFirstStylesheet = false;
				var whitespace = m.match(/^[^<]+/);
				string = ((whitespace) ? whitespace[0] : "") + cssToken;
			}
			return string;
		};
	var links = [];
	var stylesheets = [];

	if (!cssToken) {
		cssToken = "<!-- inline CSS insertion token -->";
	}

	html = html.replace(/[ \t]*<link [^>]*rel=["']?stylesheet["'][^>]*\/>[ \t]*(?:\n|\r\n)?/g, function (m) {
		links.push(m);
		return insertToken(m);
	});

	stylesheets = links.map(function (link) {
		var urlMatch = link.match(/href="([^"]+)"/);
		var mediaMatch = link.match(/media="([^"]+)"/);
		var url = urlMatch && urlMatch[1];
		var media = mediaMatch && mediaMatch[1];

		return { url: url, media: media };
	});

	var index = html.indexOf(cssToken);
	var length = cssToken.length;

	if (index == -1) {
		fail("token not found:\n" + cssToken);
	}

	var replacement = "<style " + ((cssId) ? "id=\"" + cssId + "\" " : "") + "media=\"screen\">\n\t\t\t" + css + "\n\t\t</style>\n";

	if (exposeStylesheets) {
		replacement += "\t\t<script>\n\t\t\t" + exposeStylesheets + " = [" + stylesheets.map(function (link) {
			return "{href:\"" + link.url + "\", media:\"" + link.media + "\"}";
		}).join(",") + "];\n\t\t</script>\n";
	}

	if (prefetch) {
		replacement += stylesheets.map(function (link) {
			return "\t\t<link rel=\"prefetch\" href=\"" + link.url + "\" />\n";
		}).join("");
	}

	return html.slice(0, index) + replacement + html.slice(index + length);

}

function outputError (context, msg, trace) {
	var msgStack = [context + ": " + msg];
	if (trace && trace.length) {
		msgStack.push("TRACE:");
		trace.forEach(function (t) {
			msgStack.push(" -> " + (t.file || t.sourceURL) + ": " + t.line + (t.function ? " (in function " + t.function + ")" : ""));
		});
	}
	fail(msgStack.join("\n"));
}

function fail(message) {
	system.stderr.write(message);
	phantom.exit(1);
}

function parseString(value) {
	if (value.match(/^(["']).*\1$/)) {
		value = JSON.parse(value);
	}
	if (typeof value == "string") {
		if (value.match(/^\{.*\}$/) || value.match(/^\[.*\]$/)) {
			value = JSON.parse(value);
		}
	}
	return value;
}
