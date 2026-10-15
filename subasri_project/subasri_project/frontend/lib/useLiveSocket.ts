"use client";

import { useEffect, useRef, useState } from "react";
import { WS_URL } from "./api";

export type LiveEvent =
  | { event: "traffic"; data: any }
  | { event: "attack"; data: any }
  | { event: "alert"; data: any };

export function useLiveSocket(onMessage: (msg: LiveEvent) => void): boolean {
  const handlerRef = useRef(onMessage);
  handlerRef.current = onMessage;
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let closedByClient = false;
    let retryDelay = 1000;

    function connect() {
      socket = new WebSocket(WS_URL);

      socket.onmessage = (evt) => {
        try {
          const parsed = JSON.parse(evt.data);
          handlerRef.current(parsed);
        } catch {
          // ignore malformed frames
        }
      };

      socket.onclose = () => {
        setConnected(false);
        if (closedByClient) return;
        setTimeout(connect, retryDelay);
        retryDelay = Math.min(retryDelay * 1.5, 15000);
      };

      socket.onopen = () => {
        setConnected(true);
        retryDelay = 1000;
      };
    }

    connect();

    return () => {
      closedByClient = true;
      socket?.close();
    };
  }, []);

  return connected;
}
