;;; websocket.el --- Emacs WebSocket client

;; Copyright (c) 2010 Andrew Hyatt
;;
;; Author: Andrew Hyatt <ahyatt at gmail dot com>
;; Maintainer: Andrew Hyatt <ahyatt at gmail dot com>
;; Keywords: Communication
;; Version: 0.9
;;
;; This program is free software; you can redistribute it and/or
;; modify it under the terms of the GNU General Public License as
;; published by the Free Software Foundation; either version 2 of the
;; License, or (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;; General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program; if not, write to the Free Software
;; Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
;; 02110-1301, USA.

;;; Commentary:
;; This implements RFC 6455, which can be found at
;; http://tools.ietf.org/html/rfc6455.
;;
;; Websockets are created by calling `websocket-open', which returns a
;; `websocket' struct.  Users of this library use the websocket
;; struct, and can call methods `websocket-send-text', which sends
;; text over the websocket, or `websocket-send', which sends a
;; `websocket-frame' struct, enabling finer control of what is sent.
;; A callback is passed to `websocket-open' that will retrieve
;; websocket frames called from the websocket.  Websockets are
;; eventually closed with `websocket-close'.
;;
;; Currently secure websockets (with wss addresses) are not supported.

(require 'bindat)
(require 'url-parse)
(require 'calc)
(eval-when-compile (require 'cl))

;;; Code:
(defclass websocket ()
  ((ready-state :initform connecting
                :type (member connecting open close)
                :documentation
                "The state of the connection, either CONNECTING, OPEN or CLOSE"
                :protection :public)
   (server-extensions :type list
                      :documentation "The list of extensions the server supports"
                      :protection :protected)
   (url :initarg :url
        :type string
        :documentation "The url this websocket is connecting to."
        :protection :protected)
   (protocol :initarg :protocol
             :type string
             :websocket "The protocol requested by the client"
             :protection :protected)
   (conn :initarg :conn
         :type processp
         :documentation "The connection process for this websocket."
         :protection :private)
   (accept-string :initarg :accept-string
                  :type string
                  :documentation
                  "The websocket accept string we expect from the server."
                  :protection :private)
   (inflight-input :type string
                   :initform ""
                   :documentation
                   "Input from the server that hasn't been processed yet."
                   :protection :private))
  :documentation
  "A websocket class.
This follows the W3C Websocket API, except translated to
eioio (CLOS) idioms.  The API is implemented in both the
websocket class and additional methods.

A websocket struct is created with `websocket-open'.

The W3C API \"bufferedAmount\" call is not currently implemented,
since there is no elisp API to get the buffered amount from the
subprocess.  There may, in fact, be output data buffered,
however, when the `on-message' or `close-callback' callbacks are
called.

`on-open', `on-message' and `on-close' are methods that act on this class,
and clients should override them to provide their needed functionality.")

(defmethod websocket-on-open ((ws websocket))
  "Called when the websocket has established or re-established the connection.

Putting all client initialization logic here is recommended.")

(defmethod websocket-on-message ((ws websocket) frame)
  "Called when the websocket has received FRAME.")

(defmethod websocket-on-close ((ws websocket))
  "Called when the websocket connection has been closed.")

(defmethod websocket-debug ((ws websocket) msg &rest args)
  "In the WEBSOCKET's debug buffer, send MSG, with format ARGS."
  (when websocket-debug
    (let ((buf (websocket-get-debug-buffer-create websocket)))
      (save-excursion
        (with-current-buffer buf
          (goto-char (point-max))
          (insert "[WS] ")
          (insert (apply 'format (append (list msg) args)))
          (insert "\n"))))))

(defmethod websocket-send ((websocket websocket) frame)
  "To the WEBSOCKET server, send the FRAME.
This will raise an error if the frame is illegal."
  (unless (websocket-check frame)
    (error "Cannot send illegal frame to websocket"))
  (websocket-debug websocket "Sending frame, opcode: %s payload: %s"
                   (websocket-frame-opcode frame)
                   (websocket-frame-payload frame))
  (websocket-ensure-connected websocket)
  (unless (websocket-openp websocket)
    (error "No webserver process to send data to!"))
  (process-send-string (slot-value websocket 'conn)
                       (websocket-encode-frame frame)))

(defmethod websocket-openp ((websocket websocket))
  "Check WEBSOCKET and return non-nil if it is open, and either
connecting or open."
  (and websocket
       (not (eq 'close (websocket-ready-state websocket)))
       (eq 'open (process-status (websocket-conn websocket)))))

(defmethod websocket-close ((websocket websocket))
  "Close WEBSOCKET and erase all the old websocket data."
  (websocket-debug websocket "Closing websocket")
  (when (websocket-openp websocket)
    (websocket-send websocket
                    (make-websocket-frame :opcode 'close
                                          :completep t))
    (set-slot-value websocket 'ready-state 'close))
  ;; Do we want to kill this?  It may result in on-closed not being
  ;; called.
  (kill-buffer (process-buffer (slot-value websocket 'conn))))

(defmethod websocket-ensure-connected ((websocket websocket))
  "If the WEBSOCKET connection is closed, open it."
  (unless (and (websocket-conn websocket)
               (ecase (process-status (websocket-conn websocket))
                 ((run open listen) t)
                 ((stop exit signal closed connect failed nil) nil)))
    (websocket-close websocket)
    (websocket-open (object-class websocket)
                    (websocket-url websocket)
                    :protocol (websocket-protocol websocket)
                    :extensions (websocket-extensions websocket))))

(defmethod websocket-outer-filter ((websocket websocket) output)
  "Filter the WEBSOCKET server's OUTPUT.
This will parse headers and process frames repeatedly until there
is no more output or the connection closes.  If the websocket
connection is invalid, the connection will be closed."
  (websocket-debug websocket "Received: %s" output)
  (let ((start-point)
        (end-point 0)
        (text (concat (slot-value websocket 'inflight-input) output))
        (header-end-pos))
    ;; If we've received the complete header, check to see if we've
    ;; received the desired handshake.
    (when (and (eq 'connecting (slot-value websocket 'ready-state))
               (setq header-end-pos (string-match "\r\n\r\n" text))
               (setq start-point (+ 4 header-end-pos)))
      (condition-case err
          (progn
            (websocket-verify-response-code text)
            (websocket-verify-headers websocket text))
        (error
         (websocket-close websocket)
         (error err)))
      (set-slot-value 'ready-state 'open)
      (condition-case err (websocket-on-open websocket) 
        (error (websocket-error websocket
                                "Got error from the on-open function: %s"
                                (error-message-string err)))))
    (when (eq 'open (slot-value websocket 'ready-state))
      (unless start-point (setq start-point 0))
      (let ((current-frame))
        (while (and (setq current-frame (websocket-read-frame
                                         (substring text start-point))))
          (websocket-process-frame websocket current-frame)
          (incf start-point (websocket-frame-length current-frame)))))
    (set-slot-value websocket 'inflight-input
                    (substring text (or start-point 0)))))


(defmethod websocket-verify-headers ((websocket websocket) output)
  "Based on WEBSOCKET's data, ensure the headers in OUTPUT are valid.
The output is assumed to have complete headers.  This function
will either return t or call `error'.  This has the side-effect
of populating the list of server extensions to WEBSOCKET."
  (websocket-debug websocket "Checking headers: %s" output)
  (let ((accept-string
         (concat "Sec-WebSocket-Accept: "
                 (slot-value websocket 'accept-string))))
    (websocket-debug websocket "Checking for accept header: %s" accept-string)
    (unless (string-match (regexp-quote accept-string) output)
      (error "Incorrect handshake from websocket: is this really a websocket connection?")))
  (let ((case-fold-search t))
    (websocket-debug websocket "Checking for upgrade header")
    (unless (string-match "\r\nUpgrade: websocket\r\n" output)
      (error "No 'Upgrade: websocket' header found."))
    (websocket-debug websocket "Checking for connection header")
    (unless (string-match "\r\nConnection: upgrade\r\n" output)
      (error "No 'Connection: upgrade' header found"))
    ;; TODO(ahyatt) Implement checking for extensions
    (when (slot-value websocket 'protocol)
      (websocket-debug websocket "Checking for protocol match: %s"
                       (slot-value websocket 'protocol))
      (unless (string-match
               (format "\r\nSec-Websocket-Protocol: %s\r\n"
                       (slot-value websocket 'protocol)) output)
        (error "Incorrect or missing protocol returned by the server.")))
    (let ((pos 0)
          (extensions))
      (while (and pos
                  (string-match "\r\nSec-Websocket-Extensions: \\(.*\\)\r\n"
                      output pos))
        (when (setq pos (match-end 1))
          (setq extensions (append extensions (split-string
                                               (match-string 1 output) ", ?")))))
      (let ((extra-extensions))
        (dolist (ext extensions)
          (when (not (member
                      (first (split-string ext "; ?"))
                      (slot-value websocket 'extensions)))
            (add-to-list 'extra-extensions (first (split-string ext "; ?")))))
        (when extra-extensions
          (error "Non-requested extensions returned by server: %s"
                 extra-extensions)))
      (set-slot-value websocket 'server-extensions extensions)))
  ;; return true
  t)

(defmethod websocket-process-frame ((websocket websocket) frame)
  "Using the WEBSOCKET's filter and connection, process the FRAME.
If the frame has a payload, the frame is passed to the filter
slot of WEBSOCKET.  If the frame is a ping, we reply with a pong.
If the frame is a close, we terminate the connection."
  (let ((opcode (websocket-frame-opcode frame)))
    (cond ((memq opcode '(continuation text binary))
           (condition-case err (websocket-on-message websocket frame)
             (error (websocket-error
                     websocket
                     "Got error from the on-message function: %s"
                     (error-message-string err)))))
          ((eq opcode 'ping)
           (websocket-send websocket
                           (make-websocket-frame :opcode 'pong :completep t)))
          ((eq opcode 'close)
           (delete-process (slot-value websocket 'conn))))))

(defmethod websocket-send-text ((websocket websocket) text)
  "To the WEBSOCKET, send TEXT as a complete frame."
  (websocket-send websocket (make-websocket-frame :opcode 'text :payload text
                                                  :completep t)))

(defvar websocket-debug nil
  "Set to true to output debugging info to a per-websocket buffer.
The buffer is ` *websocket URL debug*' where URL is the
URL of the connection.")

(defvar websocket-ignore-error nil
  "Set to true to suppress error messages.")

(defconst websocket-guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  "The websocket GUID as defined in RFC 6455.
Do not change unless the RFC changes.")

(defvar websocket-mask-frames t
  "If true, we mask frames as defined in the spec.
This is recommended to be true, and some servers will refuse to
communicate with unmasked clients.")

(defun websocket-genbytes (nbytes)
  "Generate NBYTES random bytes."
  (let ((s (make-string nbytes ?\s)))
    (dotimes (i nbytes)
      (aset s i (random 256)))
    s))

(defun websocket-genkey ()
  "Generate a key suitable for the websocket handshake."
  (base64-encode-string (websocket-genbytes 16)))

(defun websocket-calculate-accept (key)
  "Calculate the expect value of the accept header.
This is based on the KEY from the Sec-WebSocket-Key header."
  (base64-encode-string
   (sha1 (concat key websocket-guid) nil nil t)))

(defun websocket-get-bytes (s n)
  "From string S, retrieve the value of N bytes.
Return the value as an unsigned integer.  The value N must be a
power of 2, up to 8."
  (if (= n 8)
    (let* ((32-bit-parts
            (bindat-get-field (bindat-unpack '((:val vec 2 u32)) s) :val))
           (cval (calc-eval '("(2^32 * $ + $$)") nil
                            (aref 32-bit-parts 0) (aref 32-bit-parts 1))))
      (when (calc-eval '("$ > $$") 'pred cval most-positive-fixnum)
        (error "websocket-get-bytes: value too large to parse!"))
      (string-to-number cval))
    ;; n is not 8
    (bindat-get-field (bindat-unpack
                     `((:val
                        ,(cond ((= n 1) 'u8)
                               ((= n 2) 'u16)
                               ((= n 4) 'u32)
                               (t (error
                                   "websocket-get-bytes: Unknown N: %s" n)))))
                     s) :val)))

(defun websocket-to-bytes (val nbytes)
  "Encode the integer VAL in NBYTES of data.
NBYTES much be a power of 2, up to 8."
  (unless (or (and (< nbytes 8)
                   (< val (expt 2 (* 8 nbytes))))
              (and (= nbytes 8)
                   (calc-eval "% < 2^(8 * %%)" 'pred val nbytes)))
      (error "websocket-to-bytes: Value %d could not be expressed in %d bytes"
             val nbytes))
  (if (= nbytes 8)
      (bindat-pack `((:val vec 2 u32))
                   `((:val . [,(/ val 4294967296)
                              ,(mod val 4294967296)])))
    (bindat-pack
     `((:val ,(cond ((= nbytes 1) 'u8)
                    ((= nbytes 2) 'u16)
                    ((= nbytes 4) 'u32)
                    (t (error "websocket-to-bytes: Unknown NBYTES: %s" nbytes)))))
     `((:val . ,val)))))

(defun websocket-get-opcode (s)
  "Retrieve the opcode from first byte of string S."
  (websocket-ensure-length s 1)
  (let ((opcode (logand #xf (websocket-get-bytes s 1))))
    (cond ((= opcode 0) 'continuation)
          ((= opcode 1) 'text)
          ((= opcode 2) 'binary)
          ((= opcode 8) 'close)
          ((= opcode 9) 'ping)
          ((= opcode 10) 'pong))))

(defun websocket-get-payload-len (s)
  "Parse out the payload length from the string S.
We start at position 0, and return a cons of the payload length and how
many bytes were consumed from the string."
  (websocket-ensure-length s 1)
  (let* ((initial-val (logand 127 (websocket-get-bytes s 1))))
    (cond ((= initial-val 127)
           (websocket-ensure-length s 9)
           (cons (websocket-get-bytes (substring s 1) 8) 9))
          ((= initial-val 126)
           (websocket-ensure-length s 3)
           (cons (websocket-get-bytes (substring s 1) 2) 3))
          (t (cons initial-val 1)))))

(defstruct websocket-frame opcode payload length completep)

(defun websocket-mask (key data)
  "Using string KEY, mask string DATA according to the RFC.
This is used to both mask and unmask data."
  (apply
   'string
   (loop for b across data
         for i from 0 to (length data)
         collect (logxor (websocket-get-bytes (substring key (mod i 4)) 1) b))))

(defun websocket-ensure-length (s n)
  "Ensure the string S has at most N bytes.
Otherwise we throw the error `websocket-incomplete-frame'."
  (when (< (length s) n)
    (throw 'websocket-incomplete-frame nil)))

(defun websocket-encode-frame (frame)
  "Encode the FRAME struct to the binary representation."
  (let* ((opcode (websocket-frame-opcode frame))
         (payload (websocket-frame-payload frame))
         (fin (websocket-frame-completep frame))
         (payloadp (memq opcode '(continuation text binary)))
         (mask-key (when websocket-mask-frames  (websocket-genbytes 4))))
    (apply 'unibyte-string
           (append (list
                    (logior (cond ((eq opcode 'continuation) 0)
                                  ((eq opcode 'text) 1)
                                  ((eq opcode 'binary) 2)
                                  ((eq opcode 'close) 8)
                                  ((eq opcode 'ping) 9)
                                  ((eq opcode 'pong) 10))
                            (if fin 128 0)))
                   (when payloadp
                     (list
                      (logior
                       (if websocket-mask-frames 128 0)
                       (cond ((< (length payload) 126) (length payload))
                             ((< (length payload) 65536) 126)
                             (t 127)))))
                   (when (and payloadp (>= (length payload) 126))
                     (append (websocket-to-bytes (length payload)
                                          (cond ((< (length payload) 126) 1)
                                                ((< (length payload) 65536) 2)
                                                (t 8))) nil))
                   (when (and payloadp websocket-mask-frames)
                     (append mask-key nil))
                   (when payloadp
                     (append (if websocket-mask-frames
                                 (websocket-mask mask-key payload)
                               payload)
                             nil))))))

(defun websocket-read-frame (s)
  "Read from string S a `websocket-frame' struct with the contents.
This only gets complete frames.  Partial frames need to wait until
the frame finishes.  If the frame is not completed, return NIL."
  (catch 'websocket-incomplete-frame
    (websocket-ensure-length s 1)
    (let* ((opcode (websocket-get-opcode s))
           (fin (logand 128 (websocket-get-bytes s 1)))
           (payloadp (memq opcode '(continuation text binary)))
           (payload-len (when payloadp
                          (websocket-get-payload-len (substring s 1))))
           (maskp (and
                   payloadp
                   (= 128 (logand 128 (websocket-get-bytes (substring s 1) 1)))))
           (payload-start (when payloadp (+ (if maskp 5 1) (cdr payload-len))))
           (payload-end (when payloadp (+ payload-start (car payload-len))))
           (unmasked-payload (when payloadp
                               (websocket-ensure-length s payload-end)
                               (substring s payload-start payload-end))))
      (make-websocket-frame
       :opcode opcode
       :payload
       (if maskp
           (let ((masking-key (substring s (+ 1 (cdr payload-len))
                                         (+ 5 (cdr payload-len)))))
             (websocket-mask masking-key unmasked-payload))
         unmasked-payload)
       :length payload-end
       :completep (> fin 0)))))

(defun* websocket-open (websocket-class url &key protocol extensions)
  "Open a websocket of type WEBSOCKET-CLASS, having a connection to URL.

This returning the `websocket' class created.
The PROTOCOL argument is optional, and setting it will declare to
the server that this client supports the protocol.  We will
require that the server also has to support that protocol.

Similar logic applies to EXTENSIONS, which is a list of conses,
the car of which is a string naming the extension, and the cdr of
which is the list of parameter strings to use for that extension.
The parameter strings are of the form \"key=value\" or \"value\".
EXTENSIONS can be NIL if none are in use.  An example value would
be '(\"deflate-stream\" . (\"mux\" \"max-channels=4\")).

For each of these event handlers, the client code can store
arbitrary data in the `client-data' slot in the returned
websocket. Errors from the callbacks will be ignored.  You should
catch it in the callback function in order to recover from the
error.  Errors not caught will be messaged using `messsage'
function.  To suppress messaging errors, set
`websocket-ignore-error' to t.  You can log errors by setting
variable `websocket-debug' to t."
  (let* ((name (format "websocket to %s" url))
         (url-struct (url-generic-parse-url url))
         (key (websocket-genkey))
         (buf-name (format " *%s*" name))
         (coding-system-for-read 'binary)
         (coding-system-for-write 'binary)
         (conn (if (equal (url-type url-struct) "ws")
                   (make-network-process :name name
                                         :buffer buf-name
                                         :host (url-host url-struct)
                                         :service (if (= 0 (url-port url-struct))
                                                      80
                                                    (url-port url-struct))
                                         :nowait nil)
                 (if (equal (url-type url-struct) "wss")
                     (error "Not implemented yet")
                   (error "Unknown protocol"))))
         (websocket (make-instance websocket-class
                     :conn conn
                     :url url
                     :protocol protocol
                     :extensions (mapcar 'car extensions)
                     :accept-string (websocket-calculate-accept key))))
    (process-put conn :websocket websocket)
    (set-process-filter conn
                        (lambda (process output)
                          (let ((websocket (process-get process :websocket)))
                            (websocket-outer-filter websocket output))))
    (set-process-sentinel
     conn
     (lambda (process change)
       (let ((websocket (process-get process :websocket)))
         (websocket-debug websocket
                          "State change to %s" change)
         (unless (eq 'closed (websocket-ready-state websocket))
           (condition-case err (websocket-on-close websocket)
             (error (websocket-error
                     websocket
                     "Got error from the on-close function: %s")))))))
    (set-process-query-on-exit-flag conn nil)
    (process-send-string conn
                         (format "GET %s HTTP/1.1\r\n"
                                 (let ((path (url-filename url-struct)))
                                   (if (> (length path) 0) path "/"))))
    (websocket-debug websocket "Sending handshake, key: %s, acceptance: %s"
                     key (websocket-accept-string websocket))
    (process-send-string conn
                         (websocket-create-headers url key protocol extensions))
    (websocket-debug websocket "Websocket opened")
    websocket))

(defun websocket-create-headers (url key protocol extensions)
  "Create connections headers for the given URL, KEY, PROTOCOL and EXTENSIONS.
These are defined as in `websocket-open'."
  (format (concat "Host: %s\r\n"
                  "Upgrade: websocket\r\n"
                  "Connection: Upgrade\r\n"
                  "Sec-WebSocket-Key: %s\r\n"
                  "Origin: %s\r\n"
                  "Sec-WebSocket-Version: 13\r\n"
                  (when protocol
                    "Sec-WebSocket-Protocol: %s\r\n")
                  (when extensions
                    (format "Sec-WebSocket-Extensions: %s\r\n"
                            (mapconcat
                             (lambda (ext)
                               (concat (car ext)
                                       (when (cdr ext) "; ")
                                       (when (cdr ext)
                                         (mapconcat 'identity (cdr ext) "; "))))
                             extensions ", ")))
                  "\r\n")
          (url-host (url-generic-parse-url url))
          key
          system-name
          protocol))

(defun websocket-get-debug-buffer-create (websocket)
  "Get or create the buffer corresponding to WEBSOCKET."
  (get-buffer-create (format " *websocket %s debug*"
                             (websocket-url websocket))))

(defun websocket-error (websocket msg &rest args)
  "Report error message MSG."
  (unless websocket-ignore-error
    (apply 'message msg args))
  (apply 'websocket-debug websocket msg args))

(defun websocket-verify-response-code (output)
  "Verify that OUTPUT contains a valid HTTP response code.
The only acceptable one to websocket is responce code 101.
A t value will be returned on success, and an error thrown
if not."
  (string-match "HTTP/1.1 \\([[:digit:]]+\\)" output)
  (unless (equal "101" (match-string 1 output))
       (error "Bad HTTP response code while opening websocket connection: %s"
              (match-string 1 output)))
  t)

(defun websocket-check (frame)
  "Check FRAME for correctness, returning true if correct."
  (and (equal (not (memq (websocket-frame-opcode frame)
                         '(continuation text binary)))
              (and (not (websocket-frame-payload frame))
                   (websocket-frame-completep frame)))))

(provide 'websocket)

;;; websocket.el ends here
