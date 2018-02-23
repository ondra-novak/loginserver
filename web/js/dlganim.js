
var DialogAnim = (function(){
	
	function MainClass(playgrndElm) {
		this.playgrndElm = playgrndElm;
		this.curDlg = null;
		this.leaveAnimDur = 500;
		this.queue = new Promise(function(ok, reject){ok();});			
	}
	
	MainClass.prototype.hide = function(back) {
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
					ok();
				}.bind(this), this.leaveAnimDur);		
			}.bind(this));
		}.bind(this));
	}
	
	MainClass.prototype.show = function(element, back) {
		var name = back?"animStateEnterBack":"animStateEnter";

		element.classList.add(name);
		this.queue = this.hide(back).then(function() {
			this.playgrndElm.appendChild(element);
			this.curDlg = element;
			setTimeout(function() {
				element.classList.replace(name,"animStateActive");
			},100);
		}.bind(this))
		return this.queue; 
	}
	
	return MainClass;
		
})();
