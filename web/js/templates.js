function loadTemplate(templateRef) {
	"use strict";
	
	var templEl;
	var templName;
	if (typeof templateRef == "string") {
		templEl = document.getElementById(templateRef);
		templName = templateRef;
	}
	
	var div = document.createElement("div");	
	if (templName) {
		div.classList.add("templ_"+templName);				
	}
	
	if (templEl.content) {
		var imp = document.importNode(templEl.content,true);
		div.appendChild(imp);
	} else {
		var x = templEl.firstChild;
		while (x) {
			div.appendChild(x.cloneNode(true));
			x = x.nextSibling;
		}
	}
	return div;
};

function View(elem) {
	if (typeof elem == "string") elem = document.getElementById(elem);
	this.root = elem;	
};

View.prototype.setContent = function(elem) {
	this.clearContent();
	this.root.appendChild(elem);
};

View.prototype.clearContent = function(elem) {
	var x =  this.root.firstChild
	while (x) {
		var y = x.firstSibling; 	
		this.root.removeChild(x);
		x = y;
	}	
};

View.prototype.markSelector = function(className) {
	var items = this.root.querySelectorAll(className);
	var cnt = items.length;
	for (var i = 0; i < cnt; i++) {
		items[i].classList.add("mark");
	}
};

View.prototype.unmark = function() {
	var items = this.root.querySelector("mark");
	var cnt = items.length;
	for (var i = 0; i < cnt; i++) {
		items[i].classList.remove("mark");
	}
};

View.prototype.installKbdHandler = function() {
	if (this.kbdHandler) return;
	this.kbdHandler = function(ev) {
		var x = ev.which || ev.keyCode;
		if (x == 13 && this.defaultAction) {
			if (this.defaultAction(this)) {
				ev.preventDefault();
				ev.stopPropagation();
			}
		} else if (x == 27 && this.cancelAction) {
			if (this.cancelAction(this)) {
				ev.preventDefault();
				ev.stopPropagation();
			}			
		}		
	}.bind(this);
	this.root.addEventListener("keydown", this.kbdHandler);
};

View.prototype.setDefaultAction = function(fn) {
	this.defaultAction = fn;
	this.installKbdHandler();
};
View.prototype.setCancelAction = function(fn) {
	this.cancelAction = fn;
	this.installKbdHandler();
};

View.prototype.installFocusHandler = function(fn) {
	if (this.focusHandler) return;
	this.focusHandler = function(ev) {
		if (this.firstTabElement) {
			setTimeout(function() {
				var c = document.activeElement;
				while (c) {
					if (c == this.root) return;
					c = c.parentElement;
				}
				this.firstTabElement.focus();
			}.bind(this),1);
		}
	}.bind(this);
	this.root.addEventListener("focusout", this.focusHandler);
};

View.prototype.setFirstTabElement = function(el) {
	this.firstTabElement = el;
	this.firstTabElement.focus();
	this.installFocusHandler();
}
