import{SignIn,SimulatorFlow,SignUp,EdDSA,Point}from"../modules/TideJS/index.js";var activeOrks=[];!function(t){"use strict";function e(e){if("email"==t(e).attr("type")||"email"==t(e).attr("name")){if(null==t(e).val().trim().match(/^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{1,5}|[0-9]{1,3})(\]?)$/))return!1}else if(""==t(e).val().trim())return!1}function r(e){var r=t(e).parent();t(r).addClass("alert-validate")}function a(e){var r=t(e).parent();t(r).removeClass("alert-validate")}window.onload=async function(){const e=new SimulatorFlow({urls:["http://host.docker.internal:2000"]});activeOrks=await e.getActiveOrks();for(var r=document.getElementById("ork-drop-down"),a=0;a<activeOrks.length;a++){var o=activeOrks[a],n=document.createElement("option");n.textContent=o[1],n.value=o,r.add(n)}t("#orkloader").hide(),activeOrks.length<=0&&(t("#alert-su").text("There is no orks found !"),t("#alert-su").show())}(),t("#loader").hide(),t(".input100").each((function(){t(this).on("blur",(function(){""!=t(this).val().trim()?t(this).addClass("has-val"):t(this).removeClass("has-val")}))})),t(".validate-form-si").on("submit",(function(){var a=t(".validate-input-si .input100");t("#submit-btn-si").prop("disabled",!0);for(var o=!0,n=0;n<a.length;n++)0==e(a[n])&&(r(a[n]),o=!1);return o?async function(e,r){t("#loader").show();const a=new URLSearchParams(window.location.search);var o=new SignIn({simulatorUrl:"http://host.docker.internal:2000/"});try{if(!await EdDSA.verify(a.get("vendorUrlSig"),a.get("vendorPublic"),a.get("vendorUrl")))throw Error("Vendor URL sig is invalid");const t=await o.start(e,r,a.get("vendorPublic"));window.opener.postMessage(t,a.get("vendorUrl")),window.self.close()}catch(e){t("#alert-si").text(e),t("#alert-si").show(),t("#submit-btn-si").prop("disabled",!1),t("#loader").hide()}}(a[0].value,a[1].value):t("#submit-btn-si").prop("disabled",!1),!1})),t(".validate-form-su").on("submit",(function(){var a=t(".validate-input-su .input100");t("#submit-btn-su").prop("disabled",!0);for(var o=!0,n=0;n<a.length;n++)0==e(a[n])&&(r(a[n]),o=!1);a[1].value!=a[2].value&&(o=!1,r(a[2]));var i=t("#ork-drop-down").val();return i.length<5&&"localhost"!=window.location.hostname&&(o=!1,r("#ork-drop-down")),o?async function(e,r,a){t("#loader-su").show();var o=[];a.forEach((t=>{const e=t.split(",");o.push([e[0],e[2],Point.fromB64(e[3])])}));var n=activeOrks.sort((()=>.5-Math.random())).slice(0,5).map((t=>[t[0],t[2],Point.fromB64(t[3])])),i={cmkOrkInfo:o,cvkOrkInfo:n,simulatorUrl:"http://host.docker.internal:2000/"};const s=new URLSearchParams(window.location.search);var l=new SignUp(i);try{if(!await EdDSA.verify(s.get("vendorUrlSig"),s.get("vendorPublic"),s.get("vendorUrl")))throw Error("Vendor URL sig is invalid");const t=await l.start(e,r,s.get("vendorPublic"),s.get("vendorUrl"));window.opener.postMessage(t,s.get("vendorUrl")),window.self.close()}catch(e){t("#alert-su").text(e),t("#alert-su").show(),t("#submit-btn-su").prop("disabled",!1),t("#loader-su").hide()}}(a[0].value,a[1].value,i):t("#submit-btn-su").prop("disabled",!1),!1})),t("#ork-drop-down").change((function(){a(this)})),t(".validate-form-si .input100").each((function(){t(this).focus((function(){a(this)}))}))}(jQuery);