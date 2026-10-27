import React, { useState } from 'react';
import { Send, Bot, User, Terminal } from 'lucide-react';
import { CopilotMessage } from '../../types';

export const SocCopilotChatView: React.FC = () => {
  const [messages, setMessages] = useState<CopilotMessage[]>([
    {
      id: '1',
      sender: 'assistant',
      content: 'Hola, soy el asistente forense SOC Copilot (LangChain + MITRE ATT&CK). ¿Qué vector deseas analizar hoy?',
      suggested_actions: [
        'Mitigar campaña de Quishing (QR)',
        'Analizar homógrafo xn--bnco-qqa.com',
        'Controles PCI-DSS Req 8 para credenciales',
      ],
      timestamp: '10:00 AM',
    },
  ]);
  const [input, setInput] = useState('');
  const [isSending, setIsSending] = useState(false);

  const sendMessage = async (textToSend: string) => {
    if (!textToSend.trim()) return;

    const userMsg: CopilotMessage = {
      id: Date.now().toString(),
      sender: 'user',
      content: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsSending(true);

    try {
      const response = await fetch('http://localhost:8000/api/v1/ai/copilot-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: textToSend }),
      });

      if (response.ok) {
        const data = await response.json();
        setMessages((prev) => [
          ...prev,
          {
            id: (Date.now() + 1).toString(),
            sender: 'assistant',
            content: data.reply,
            suggested_actions: data.suggested_actions,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          },
        ]);
      }
    } finally {
      setIsSending(false);
    }
  };

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 rounded-2xl h-[620px] flex flex-col shadow-sm overflow-hidden">
      <div className="px-6 py-4 bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-blue-600/10 border border-blue-500/20 flex items-center justify-center text-blue-600 dark:text-blue-400">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              SOC Copilot <span className="text-[10px] px-2 py-0.5 bg-blue-50 dark:bg-blue-900/40 text-blue-600 dark:text-blue-300 rounded-md font-semibold">LangChain RAG</span>
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">Asistente de respuesta a incidentes</p>
          </div>
        </div>
        <div className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
          <Terminal className="w-4 h-4 text-emerald-500" />
          <span>Ollama Llama 3</span>
        </div>
      </div>

      <div className="flex-1 p-6 overflow-y-auto space-y-4">
        {messages.map((m) => (
          <div key={m.id} className={`flex gap-3 ${m.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
            {m.sender === 'assistant' && (
              <div className="w-7 h-7 rounded-full bg-blue-600 text-white flex items-center justify-center text-xs shrink-0 mt-1">
                <Bot className="w-4 h-4" />
              </div>
            )}
            <div className={`max-w-[78%] rounded-2xl p-4 text-xs leading-relaxed ${
              m.sender === 'user'
                ? 'bg-blue-600 text-white'
                : 'bg-slate-50 dark:bg-slate-950 border border-slate-200/80 dark:border-slate-800 text-slate-800 dark:text-slate-200'
            }`}>
              <p>{m.content}</p>
              {m.suggested_actions && m.suggested_actions.length > 0 && (
                <div className="mt-3 pt-3 border-t border-slate-200 dark:border-slate-800 flex flex-wrap gap-1.5">
                  {m.suggested_actions.map((act, idx) => (
                    <button
                      key={idx}
                      onClick={() => sendMessage(act)}
                      className="text-[11px] px-2.5 py-1 rounded-lg bg-white dark:bg-slate-900 hover:bg-blue-50 dark:hover:bg-slate-800 text-blue-600 dark:text-blue-400 border border-slate-200 dark:border-slate-700 font-medium transition-colors"
                    >
                      {act}
                    </button>
                  ))}
                </div>
              )}
              <span className={`text-[9px] block text-right mt-1.5 ${m.sender === 'user' ? 'text-blue-200' : 'text-slate-400'}`}>
                {m.timestamp}
              </span>
            </div>
            {m.sender === 'user' && (
              <div className="w-7 h-7 rounded-full bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-200 flex items-center justify-center text-xs shrink-0 mt-1">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}
        {isSending && (
          <div className="text-xs text-slate-400 flex items-center gap-2">
            <Bot className="w-4 h-4 animate-spin text-blue-500" /> Analizando...
          </div>
        )}
      </div>

      <div className="p-4 bg-slate-50 dark:bg-slate-950 border-t border-slate-200 dark:border-slate-800">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            sendMessage(input);
          }}
          className="flex gap-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Escribe una consulta forense o pide un plan de mitigación..."
            className="flex-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 px-4 py-2.5 rounded-xl text-xs text-slate-900 dark:text-white focus:outline-none focus:border-blue-500"
          />
          <button
            type="submit"
            disabled={!input.trim() || isSending}
            className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white px-5 py-2.5 rounded-xl text-xs font-semibold flex items-center gap-1.5"
          >
            <Send className="w-3.5 h-3.5" /> Enviar
          </button>
        </form>
      </div>
    </div>
  );
};
