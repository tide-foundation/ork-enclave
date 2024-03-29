// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

import { SignIn, ChangePassword, SimulatorFlow, SignUp, EdDSA, Point } from "../modules/TideJS/index.js";

var activeOrks = [];

(function ($) {
    "use strict";
    window.onload = getAllOrks();
    $('#loader').hide();
    /*==================================================================
    [ Focus input ]*/
    $('.input100').each(function(){
        $(this).on('blur', function(){
            if($(this).val().trim() != "") {
                $(this).addClass('has-val');
            }
            else {
                $(this).removeClass('has-val');
            }
        })    
    })
  
    /*==================================================================
    [ Validate ]*/
    

    $('.validate-form-si').on('submit',function(){
        var input = $('.validate-input-si .input100');

        $('#submit-btn-si').prop('disabled', true);
        var check = true;
        
        for(var i=0; i<input.length; i++) {
            if(validate(input[i]) == false){
                showValidate(input[i]);
                check=false;
            }
        }  
        if(check){
            signin(input[0].value , input[1].value); 
        }  
        else
            $('#submit-btn-si').prop('disabled', false);
        return false;
    });

    $('.validate-form-cp').on('submit',function(){
        var input = $('.validate-input-cp .input100');

        $('#submit-btn-cp').prop('disabled', true);
        var check = true;
        
        for(var i=0; i<input.length; i++) {
            if(validate(input[i]) == false){
                showValidate(input[i]);
                check=false;
            }
        }  
        if (input[2].value != input[3].value) {
            check = false;
            showValidate(input[2]);
        }
        if(check){
            changePassword(input[0].value, input[1].value, input[2].value);
        }  
        else
            $('#submit-btn-cp').prop('disabled', false);
        return false;
    });

    $('.validate-form-su').on('submit', function () {
        var input = $('.validate-input-su .input100');
        $('#submit-btn-su').prop('disabled', true);
        var check = true;

        for (var i = 0; i < input.length; i++) {
            if (validate(input[i]) == false) {
                showValidate(input[i]);
                check = false;
            }
        }
        if (input[1].value != input[2].value) {
            check = false;
            showValidate(input[2]);
        }
        var values = $('#ork-drop-down').val();
        if (values.length < 5 && window.location.hostname != "localhost") {
            check = false;
            showValidate('#ork-drop-down');
        }
        if (check){
            signup(input[0].value, input[1].value, values);
        }
            
        else
            $('#submit-btn-su').prop('disabled', false);
        return false;
    });

    $('#ork-drop-down').change(function () {
        hideValidate(this);
    });

    $('.validate-form-si .input100').each(function(){
        $(this).focus(function(){
           hideValidate(this);
        });  
    });

    function validate(input) {
        if ($(input).attr('type') == 'email' || $(input).attr('name') == 'email') {
            if ($(input).val().trim().match(/^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{1,5}|[0-9]{1,3})(\]?)$/) == null) {
                return false;
            }
        }
        else {
            if ($(input).val().trim() == '') {
                return false;
            }
        }
    }

    function showValidate(input) {
        var thisAlert = $(input).parent();

        $(thisAlert).addClass('alert-validate');
    }

    function hideValidate(input) {
        var thisAlert = $(input).parent();

        $(thisAlert).removeClass('alert-validate');
    }

    async function getAllOrks() {

        activeOrks = await SimulatorFlow.GetActiveOrks(); 
       
        var select = document.getElementById("ork-drop-down");
        for(var i = 0; i < activeOrks.length; i++) {
            var opt = activeOrks[i];
            var el = document.createElement("option");
            el.textContent = opt.name;
            el.value = JSON.stringify(opt);
            if(i < 5) el.selected = "selected" // threshold / n constant here
            select.add(el);                       
        } 
        
        $('#orkloader').hide();
        if(activeOrks.length <= 0)  {
            $('#alert-su').text("There is no orks found !"); 
            $('#alert-su').show();
        }  
            
    }

    async function signin(user, pass) {
        $('#loader').show();
        
        const params = new URLSearchParams(window.location.search);
        const mode = params.get("mode");
        const modelToSign = params.get("modelToSign") == "" ? null : params.get("modelToSign");

        var config = {
            mode: mode,
            modelToSign: modelToSign
        } 
        const signin = new SignIn(config);
        try{
            if(!(await EdDSA.verify(params.get("vendorUrlSig"), params.get("vendorPublic"), params.get("vendorUrl")))) throw Error("Vendor URL sig is invalid")

            
            let resp;
            if(mode == "default" || modelToSign != null){
                // default mode (no model to sign) or model to sign already exists
                await signin.start(user, pass, params.get("vendorPublic"));
                resp = await signin.continue(modelToSign)
            }else{
                // wait for response (model to sign) - ok to not remove event handler because this page will close soon anyways 
                const waitForSignal = () => {
                    return new Promise((resolve) => {
                        const handler = (event) =>{
                            window.removeEventListener("message", handler);
                            if(event.origin == new URL(params.get("vendorUrl")).origin) resolve(event.data); // resolve promise when window listener has recieved msg
                        }
                        window.addEventListener("message", handler, false);
                    });
                }
                const userData = await signin.start(user, pass, params.get("vendorPublic")); // get jwt for this vendor from sign in flow
                const pre_model = waitForSignal();
                window.opener.postMessage(userData, params.get("vendorUrl")); // post jwt to vendor window which opened this enclave
                const model = await pre_model; // model to sign from page calling the enclave
                if(model === "VENDOR ERROR: Close Tide Enlcave") window.self.close(); // in case of vendor error
                
                resp = await signin.continue(model);
            }

            window.opener.postMessage(resp, params.get("vendorUrl")); // post jwt to vendor window which opened this enclave
            window.self.close();
        }catch(e){
            $('#alert-si').text(e);
            $('#alert-si').show();
            $('#submit-btn-si').prop('disabled', false);
            $('#loader').hide();
        }
    }

    async function signup(user, pass, selectedOrks) {
        $('#loader-su').show();
        /**
         * @type {[string, string, Point][]}
         */
        var cmkOrkInfo = [];
        selectedOrks.forEach(element => {
            const myArray = JSON.parse(element);
            cmkOrkInfo.push([myArray.id, myArray.url, Point.fromB64(myArray.public)]);
        });
        var cvkOrkInfo = activeOrks.sort(() => 0.5 - Math.random()).slice(0, 5).map(a => [a.id, a.url, Point.fromB64(a.public)]);// get first 5 random orks as cvk orks
        
        const params = new URLSearchParams(window.location.search);
        const mode = params.get("mode");
        const modelToSign = params.get("modelToSign") == "" ? null : params.get("modelToSign");

        var config = {
            cmkOrkInfo: cmkOrkInfo,
            cvkOrkInfo: cvkOrkInfo
        }
        const signup = new SignUp(config);
        try{
            if(!(await EdDSA.verify(params.get("vendorUrlSig"), params.get("vendorPublic"), params.get("vendorUrl")))) throw Error("Vendor URL sig is invalid")

            let resp;
            if(mode == "default" || modelToSign != null){
                // default mode (no model to sign) or model to sign already exists
                await signup.start(user, pass, params.get("vendorPublic"), params.get("vendorUrl"));
                resp = await signup.continue(modelToSign)
            }else{
                // wait for response (model to sign) - ok to not remove event handler because this page will close soon anyways 
                const waitForSignal = () => {
                    return new Promise((resolve) => {
                        const handler = (event) =>{
                            window.removeEventListener("message", handler);
                            if(event.origin == new URL(params.get("vendorUrl")).origin) resolve(event.data); // resolve promise when window listener has recieved msg
                        }
                        window.addEventListener("message", handler, false);
                    });
                }
                const userData = await signup.start(user, pass, params.get("vendorPublic"), params.get("vendorUrl")); // get jwt for this vendor from sign in flow
                const pre_model = waitForSignal();
                window.opener.postMessage(userData, params.get("vendorUrl")); // post jwt to vendor window which opened this enclave
                const model = await pre_model; // model to sign from page calling the enclave
                if(model === "VENDOR ERROR: Close Tide Enlcave") window.self.close(); // in case of vendor error
                
                resp = await signup.continue(model);
            }
            window.opener.postMessage(resp, params.get("vendorUrl")); // post jwt to vendor window which opened this enclave
            window.self.close();
        }catch(e){
            $('#alert-su').text(e);
            $('#alert-su').show();
            $('#submit-btn-su').prop('disabled', false);
            $('#loader-su').hide();
        }
        
    }

    async function changePassword(username, oldPassword, newPassword){
        $('#loader-cp').show();
        const params = new URLSearchParams(window.location.search);
        try{
            if(!(await EdDSA.verify(params.get("vendorUrlSig"), params.get("vendorPublic"), params.get("vendorUrl")))) throw Error("Vendor URL sig is invalid")

            const mode = params.get("mode");
            const modelToSign = params.get("modelToSign") == "" ? null : params.get("modelToSign");

            const changePassword = new ChangePassword();
            let resp;
            if(mode == "default" || modelToSign != null){
                // default mode (no model to sign) or model to sign already exists
                await changePassword.start(username, oldPassword, newPassword, params.get("vendorPublic"));
                resp = await changePassword.continue(mode, modelToSign);
            }else{
                const userData = await changePassword.start(username, oldPassword, newPassword, params.get("vendorPublic"));
                const pre_model = waitForSignal(new URL(params.get("vendorUrl")).origin);
                window.opener.postMessage(userData, params.get("vendorUrl")); // post jwt to vendor window which opened this enclave
                const model = await pre_model; // model to sign from page calling the enclave
                if(model === "VENDOR ERROR: Close Tide Enlcave") window.self.close(); // in case of vendor error
                resp = await changePassword.continue(mode, model);
            }
            window.opener.postMessage(resp, params.get("vendorUrl")); // post jwt to vendor window which opened this enclave
            window.self.close();
        }catch(e){
            $('#alert-cp').text(e);
            $('#alert-cp').show();
            $('#submit-btn-cp').prop('disabled', false);
            $('#loader-cp').hide();
        }
    }

    function waitForSignal(origin){
        return new Promise((resolve) => {
            const handler = (event) =>{
                window.removeEventListener("message", handler);
                if(event.origin == origin) resolve(event.data); // resolve promise when window listener has recieved msg
            }
            window.addEventListener("message", handler, false);
        });
    }

    
})(jQuery);

