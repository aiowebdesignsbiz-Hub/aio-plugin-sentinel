( function() {
	'use strict';

	function showToast( type, message, details ) {
		var toast = document.createElement( 'div' );
		toast.className = 'aiomeg-toast aiomeg-toast-' + type;
		toast.setAttribute( 'role', 'status' );
		toast.innerHTML = '<strong>' + message + '</strong>' + ( details ? '<span>' + details + '</span>' : '' );
		document.body.appendChild( toast );
		window.setTimeout( function() { toast.classList.add( 'is-visible' ); }, 10 );
	}

	function scan() {
		var button = document.querySelector( '.aiomeg-run-scan' );
		var progress = document.querySelector( '.aiomeg-scan-progress' );
		if ( ! button || ! window.aiomegAdmin ) {
			return;
		}
		button.disabled = true;
		button.setAttribute( 'aria-disabled', 'true' );
		if ( progress ) {
			progress.hidden = false;
		}

		var data = new URLSearchParams();
		data.append( 'action', 'aiomeg_run_scan' );
		data.append( 'nonce', window.aiomegAdmin.nonce );
		window.fetch( window.aiomegAdmin.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
			body: data.toString()
		} ).then( function( response ) {
			return response.json();
		} ).then( function( response ) {
			if ( ! response.success ) {
				throw new Error( response.data && response.data.message ? response.data.message : 'The scan did not complete.' );
			}
			var result = response.data;
			if ( result.criticalCount ) {
				showToast( 'error', result.criticalCount + ' critical security item(s) need investigation.', result.findings && result.findings.length ? result.findings.join( ' | ' ) : 'Open AIO Malicious Extension Guard for details.' );
				window.setTimeout( function() { window.location.reload(); }, 5000 );
				return;
			}
			var message = 'Scan complete. No known critical malware indicators were found.';
			var details = result.fileCount + ' files checked.';
			if ( result.reviewCount ) {
				details += ' ' + result.reviewCount + ' review-level item(s) remain for qualified review; none were quarantined.';
			}
			showToast( 'success', message, details );
			window.setTimeout( function() { window.location.reload(); }, 2600 );
		} ).catch( function( error ) {
			showToast( 'error', 'The scan did not complete.', error.message || 'Check the WordPress server error log, then try again.' );
			button.disabled = false;
			button.removeAttribute( 'aria-disabled' );
			if ( progress ) {
				progress.hidden = true;
			}
		} );
	}

	document.addEventListener( 'click', function( event ) {
		if ( event.target && event.target.classList.contains( 'aiomeg-run-scan' ) ) {
			event.preventDefault();
			scan();
		}
	} );

	document.addEventListener( 'DOMContentLoaded', function() {
		var outcome = document.querySelector( '.aiomeg-outcome-notice[data-aiomeg-toast]' );
		if ( outcome ) {
			showToast( outcome.getAttribute( 'data-aiomeg-toast' ), outcome.textContent.trim() );
		}
	} );
}() );
