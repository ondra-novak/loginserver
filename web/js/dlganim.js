
var DialogAnim = (function(){
	"use strict"
	
	
	function MainClass(playgrndElm) {
		if (typeof playgrndElm == "string") {
			playgrndElm = document.getElementById(playgrndElm);
		}
		this.playgrndElm = playgrndElm;
		this.curDlg = null;
		this.leaveAnimDur = 500;
		this.queue = new Promise(function(ok, reject){ok();});
		playgrndElm.classList.add("dlg_playground");
		playgrndElm.classList.add("hidden");
		
	}
	
	MainClass.prototype.hide = function(back, keep_lightbox) {
		var name = back?"animStateLeaveBack":"animStateLeave";
		return this.queue = this.queue.then(function(){
			
			var d = this.curDlg;
			this.curDlg = null;
			if (d == null) return;
			
			d.classList.replace("animStateActive",name);
			return new Promise(function(ok) {

				setTimeout(function(){
					d.classList.remove(name);
					this.playgrndElm.removeChild(d);
					if (this.curDlg == null && !keep_lightbox) {
						this.playgrndElm.classList.add("hidden");
					}
					ok();
				}.bind(this), this.leaveAnimDur);		
			}.bind(this));
		}.bind(this));
	}
	
	MainClass.prototype.showDlg = function(element, back) {
		var name = back?"animStateEnterBack":"animStateEnter";

		element.classList.add(name);
		this.queue = this.hide(back).then(function() {
			this.playgrndElm.appendChild(element);
			this.curDlg = element;
			this.playgrndElm.classList.remove("hidden");
			setTimeout(function() {
				element.classList.replace(name,"animStateActive");
			},100);
		}.bind(this))
		return this.queue; 
	}

	MainClass.prototype.makeDlg = function(element) {
		var el = document.createElement("div");
		el.classList.add("dlg");
		el.appendChild(element);
		return el;		
	}
	
	MainClass.prototype.show = function(element, back) {
		return this.showDlg(this.makeDlg(element),back);
	}

	
	return MainClass;


})();
