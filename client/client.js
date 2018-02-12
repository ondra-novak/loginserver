///Initializes RPC client
/**
 * @param rpc_url - url of rpc server
 * @param options - optional object. Currently only one option is available "useMulticall" which can be true or false. Default is true.
 *                   If useMulticall is true, then multiple requests are packed into single "Server.multicall" call.  
 *                   If useMulticall is false, then multiple requests are no longer packed. They are sent separatedly each for single request.
 *                   Note that object can process one request at time, other requests are queued or combined into multicall pack
 * XXX is name of variable that will contain list of methods
 *
 * Use operator new to construct object. Object will map all methods to the object as standard javascript methods
 */
function RpcClient (rpc_url,  options) {

	var lastIdent = 0;
	var connection = new XMLHttpRequest();
	
	var requests = [];
	var requests_promises = [];
	
	//initialize promise to filled
	var exchangePromise = new Promise(function(ok,fail) {
		ok(true);
	});
	
	var useMulticall = true;

	var url = rpc_url; //url rpc serveru
	
	var me = this;

	var doCall = function(method, args) {
		return new Promise(function(ok,fail) {
		
			var idle = requests.length == 0;
			requests.push([method,args]);
			requests_promises.push([ok,fail]);
			
			if (idle || !useMulticall) exchangePromise = exchangePromise.then(sheduleRequest);
		});
	}

	
	var getRequests = function() {
		if (useMulticall) {
			var p = requests;
			requests = [];
			return p;
		} else {
			return [requests.shift()];
		}
	}

	var getPromises = function() {
		if (useMulticall) {
			var p = requests_promises;
			requests_promises = [];
			return p;
		} else {
			return [requests_promises.shift()];
		}
	}

	var sheduleRequest = function(x) {		
			var r = getRequests();
			var rp = getPromises();
			if (r.length == 0) return true;
			else if (r.length == 1) {
				return new Promise(function(ok,fail) {
					doCall2(r[0][0], r[0][1]).then(
							function(v) {
								rp[0][0](v);
								ok(true);
								return v;
							},
							function(v) {
								rp[0][1](v);
								ok(true);
								return v;
							});
				});
			}
			else {
				return new Promise(function(ok,fail) {
					doCall2("Server.multicall",r).then(
						function(v) {
							
							var i;
							var e = 0;
							for (i = 0; i < v.results.length; i++) {
								if (v.results[i] === null) {
									rp[i][1](v.errors[e++]);
								} else {
									rp[i][0](v.results[i]);
								}
							}

							ok(true);
							return v;
							
						}, function(e) {
							
							var i;
							for (i = 0; i < rp.length; i++) {
								rp[i][1](e);
							}
							ok(true);
							return e;
						});
				
				});
		}					
				
	}
		
    var updateContext = function(c) {
    	var changed = false;
		for (var i in c) {
			changed = true;
			if (i == null) delete me.context[i];
			else me.context[i] = c[i];
		}
    }

    this.updateContext = function(c) {
  	  updateContext(c);
    }
    
	
	var doCall2 = function(method,args) {
		return new Promise(function(ok,fail) {
			var request = {
					id:lastIdent,
					method:method,
					params:args,
					context:me.context,
					jsonrpc:"2.0"
			};
			lastIdent++;
	        var data = JSON.stringify(request);
	        connection.onreadystatechange =  function() {            	
	            if (connection.readyState == 4  ) {
	                     if (connection.status == 200) {
	                    	var response = connection.responseText;
	                        var r = JSON.parse(response);
	                        if (r.error) {
	                        	fail(r.error);
	                        } else {
				    			if (r.context) updateContext(r.context);
	                        	ok(r.result);
	                        }
	                     } else {
	                         
	                    	 me.onConnectionError(connection.status,request,
	                    		function(e) {
	                    		 	if (e.result) {
	                    		 		if (e.context) updateContext(e.context);
	    	                        	ok(e.result);
	                    		 	} else if (e.error) {
	                    		 		fail(e.error);
	                    		 	} else if (e) {
	                    		 		doCall2(request.method,request.params)
	                    		 			.then(function(v) {ok(v);},function(v) {fail(v);});
	                    		 	} else {
	                    		 		fail(RpcClient.FAILED);
	                    		 	}                        		   
	                    	 	});
	                     }
	            }
	        }
	        connection.open("POST", url, true);
	        connection.setRequestHeader("Accept","application/json");
	        connection.setRequestHeader("Content-Type","application/json");
	        connection.send(data);
		});

	}

	var getMethods = function() {
		return new Promise(function(ok,fail) {
	        connection.onreadystatechange =  function() {            	
	            if (connection.readyState == 4  ) {
	                     if (connection.status == 200) {
	                    	var response = connection.responseText;
	                        var r = JSON.parse(response);
	                        ok(r);
	                     } else {
	                    	 fail(connection.status);
	                     }
	            }
	        }
	        connection.open("POST", url, true);
	        connection.setRequestHeader("Accept","application/json");
	        connection.setRequestHeader("Content-Type","application/json");
	        connection.send("");
		});
	}

	
	var regMethod = function(obj, locname, remotename) {
		var k = locname.indexOf('.');
		var r = remotename;
		if (k == -1) {
			obj[locname] = function() {    				
				var args = new Array();    				
				for (var x =0; x < arguments.length;x++) {
					args.push(arguments[x]);
				}
			    return doCall(r,args);
			}
		} else {
			var subloc = locname.substr(0,k);
			var outloc = locname.substr(k+1);
			if (!(subloc in obj)) obj[subloc] = new Object();
			regMethod(obj[subloc],outloc,remotename);
		}    		
	}
	

	var initmethods = true;

	if (options) {
		if (options.hasOwnProperty("useMulticall")) useMulticall = options.useMulticall;
		if (options.hasOwnProperty("onConnectionError")) this.onConnectionError = options.onConnectionError;
		if (options.hasOwnProperty("methods")) {
			var ml = options["methods"];
			ml.forEach(function(name) { 
				regMethod(me, name,name)});			
			initmethods = false;
			}
		
	}

	if (initmethods) {

		me.ready = getMethods().then(function(method_list){
				method_list.forEach(function(name) {
					regMethod(me,name,name);
			});
				return method_list;
		})
	}
	
		
	this.context = new Object();
	this.call = doCall;
	
};

///Default behaviour for http-error. You can write own handler
/**
 * @param status status code - read from XMLHttpRequest()
 * @param request whole request object. 
 * @param resolve callback function to resolve this situation. If called with true, then request is repeated.
 *   if called with false, then request is failed. If called with object, then object must be formatted as
 *   standard JSON response. This response is then used to fullfil or reject apropriate promise on that request.
 *
 * @note Note that for Server.multicall call, you should return apropriate response
 * 
 */
RpcClient.prototype.onConnectionError = function(status,request,resolve) {
	if (status == 404) resolve(false);
	else resolve(confirm("Error " + status + " while processing request: " + request.method +". Retry?"));
}


///canceled multicall request
RpcClient.CANCELED = "canceled";
RpcClient.FAILED = "failed";

///Extends promise - function store
/** Stores result to object under specified key once the promise is filled.  */
Promise.prototype.store = function(obj,name) {
	return this.then(function (v) {
		obj[name] = v;
		return v;
	});
}

///Extends promise - function log
/** Dumps result to console  */
Promise.prototype.log = function() {
	return this.then(function (v) {
		console.log(v)
		return v;
	},function(e) {
		console.error(e)
		return e;		
	});
}


