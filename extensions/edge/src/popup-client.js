// Popup transport only. The background owns persistence and filtering.
export function createPopupClient(runtime) {
  return Object.freeze({async request(message) {
    if (!message || typeof message.type !== 'string') throw new TypeError('Message type required');
    const response = await runtime.sendMessage(message);
    if (!response?.ok) throw new Error(response?.error ?? 'RequestFailed');
    return response;
  }});
}
