// usulnet core client-side helpers.
//
// Loaded via `<script defer>` from the base layout. Exposes a single
// `window.usulnet` namespace and wires the global HTMX lifecycle
// (toast events from HX-Trigger, error feedback). Theme bootstrap is
// in theme-init.js — that one loads synchronously before CSS to
// prevent FOUC; everything else lives here so it can be cached.

(function () {
	'use strict';

	var STATUS_MESSAGES = {
		401: 'Session expired - redirecting to login',
		403: 'Permission denied',
		404: 'Resource not found',
		422: 'Validation error',
		429: 'Too many requests - please wait',
		500: 'Server error - please try again',
		502: 'Service temporarily unavailable',
		503: 'Service temporarily unavailable',
		0: 'Network error - check your connection',
	};

	var TOAST_COLORS = {
		success: 'bg-green-600 border-green-500',
		error: 'bg-red-600 border-red-500',
		warning: 'bg-yellow-600 border-yellow-500',
		info: 'bg-primary-600 border-primary-500',
	};

	var TOAST_ICONS = {
		success: 'fa-check-circle',
		error: 'fa-exclamation-circle',
		warning: 'fa-exclamation-triangle',
		info: 'fa-info-circle',
	};

	window.usulnet = {
		toggleTheme: function () {
			var html = document.documentElement;
			var isDark = html.classList.contains('dark');
			var newTheme = isDark ? 'light' : 'dark';
			html.classList.remove('dark', 'light');
			html.classList.add(newTheme);
			localStorage.setItem('usulnet-theme', newTheme);
			var icon = document.getElementById('theme-toggle-icon');
			if (icon) {
				icon.className = 'fas ' + (newTheme === 'dark' ? 'fa-moon' : 'fa-sun');
			}
		},

		toast: function (message, type, duration) {
			if (!type) type = 'info';
			if (duration === undefined) duration = 4000;
			var container = document.getElementById('toast-container');
			if (!container) return;
			var toast = document.createElement('div');
			var colorClass = TOAST_COLORS[type] || TOAST_COLORS.info;
			var iconClass = TOAST_ICONS[type] || TOAST_ICONS.info;
			toast.className = colorClass + ' text-white px-4 py-3 rounded-lg shadow-lg border-l-4 flex items-center gap-3 animate-slide-in max-w-sm';
			toast.innerHTML =
				'<i class="fas ' + iconClass + '"></i>' +
				'<span class="toast-message flex-1 text-sm"></span>' +
				'<button onclick="this.parentElement.remove()" class="text-white/70 hover:text-white ml-2">' +
				'<i class="fas fa-times text-xs"></i></button>';
			toast.querySelector('.toast-message').textContent = message;
			container.appendChild(toast);
			if (duration > 0) {
				setTimeout(function () {
					if (toast.parentElement) toast.remove();
				}, duration);
			}
		},

		formatBytes: function (bytes, decimals) {
			if (decimals === undefined) decimals = 2;
			if (bytes === 0) return '0 B';
			var k = 1024;
			var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
			var i = Math.floor(Math.log(bytes) / Math.log(k));
			return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
		},
	};

	// HTMX lifecycle wiring: surface HX-Trigger toast events and
	// translate transport / status errors into user-facing toasts.
	document.body.addEventListener('htmx:afterRequest', function (evt) {
		var xhr = evt.detail.xhr;
		if (!xhr) return;
		var trigger = xhr.getResponseHeader('HX-Trigger');
		if (!trigger) return;
		try {
			var data = JSON.parse(trigger);
			if (data.showToast) {
				usulnet.toast(data.showToast.message, data.showToast.type);
			}
		} catch (e) {
			// HX-Trigger may carry a bare event name (not JSON) — that's
			// not addressed to us. Ignore silently.
		}
	});

	document.body.addEventListener('htmx:responseError', function (evt) {
		var xhr = evt.detail.xhr;
		var status = xhr ? xhr.status : 0;
		var message = STATUS_MESSAGES[status] || 'Request failed';
		if (status === 401) {
			setTimeout(function () {
				window.location.href = '/login';
			}, 1500);
		}
		usulnet.toast(message, 'error', 6000);
	});

	document.body.addEventListener('htmx:timeout', function () {
		usulnet.toast('Request timed out', 'warning', 6000);
	});

	document.body.addEventListener('htmx:sendError', function () {
		usulnet.toast('Connection error - check your network', 'error', 6000);
	});
})();
