var rootView;
var dlganim;
var rpc;

function doLogin(errType) {
	return new Promise(function(ok,cancel) {
		var d = loadTemplate("loginPage");
		var view = new View(d);
		view.setDefaultAction(function() {
			var uname = d.querySelector(".uname").value;
			var pwd = d.querySelector(".pwd").value;
			dlganim.hide(false,true);
			rpc.User.login({"user":uname,"password":pwd})
				.then(function(x) {
					ok(x);					
				},function(e) {
					doLogin(e.code).then(ok,cancel);
				})		
		});
		view.setCancelAction(function() {dlganim.hide().then(cancel);});
		
		dlganim.show(d,!!errType).then(function(){
			view.setFirstTabElement(d.querySelector(".uname"));
		});
		
		d.querySelector(".cancel").addEventListener("click",view.cancelAction);				
		d.querySelector(".login").addEventListener("click",view.defaultAction);
		if (errType) {
			view.markSelector(".err"+errType);		
		}
	});
}

function isEmail(x) {
	var a = x.indexOf("@");
	if (a > 0) {
		var c = x.substr(a+1);
		var b = c.indexOf(".");
		if (b > 0)
			return true;
	}
	return false;
}

function doSignup() {
	return new Promise(function(ok,cancel) {
		var d = loadTemplate("createAccPage");
		var view = new View(d);
		var cp_resp = null;
		var emlfld = d.querySelector(".email");

		function dlgRules() {
			var eml = emlfld.value;
			var canCont = cp_resp && isEmail(eml);
			d.querySelector(".create").disabled = canCont?false:true;
			return canCont;
		}
		
		dlganim.show(d).then(function(){
			grecaptcha.render(d.querySelector(".g-recaptcha"),{
				sitekey:"6Lem8UYUAAAAAB8YThTYDws-oR0JIvbPUwPbB85S",
				callback:function(chng) {
					cp_resp = chng;
					if (dlgRules())  {
						view.defaultAction();
					}
				},
				"expired-callback": function() {
					cp_resp = null;
					dlgRules();
				}			
			});
			view.setFirstTabElement(emlfld);
		});
		view.setCancelAction(function() {dlganim.hide().then(cancel);});
		view.setDefaultAction(function() {
			var eml = emlfld.value;
			if (isEmail(eml)) {
				dlganim.hide();
				return;
			}
		});
		d.querySelector(".cancel").addEventListener("click",view.cancelAction);
		emlfld.addEventListener("input", dlgRules);
		dlgRules();
	});
	
	
}

function loginPage() {
	rootView.setContent(loadTemplate("rootPage"));
	login.addEventListener("click", doLogin.bind(null,null));
	signup.addEventListener("click", doSignup.bind(null,null));
}

function start() {
	
	rootView = new View("content");
	dlganim = new DialogAnim("dialogs");
	var r = new RpcClient("/RPC");
	r.createObject().then(function(x) {
		rpc = x;
		loginPage();	
	});
}