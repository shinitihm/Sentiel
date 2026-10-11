# Sentiel

**Um SOC pessoal com triagem por IA que funciona com qualquer LLM.**
Detecção baseada em Sigma na sua própria máquina, um modelo de linguagem para explicar e priorizar o que foi encontrado, e um design que não deixa esse modelo ser convencido a esconder um alerta.

[English](README.md)

```
pip install .
sentiel demo --no-ai                      # 7 ataques simulados, sem modelo
sentiel demo -m ollama/llama3.1:8b        # o mesmo, com triagem por IA local
```

## O que faz

- **Coleta** Windows Event Log (Security, System, Sysmon), `auth.log` do Linux e JSON Lines genérico.
- **Detecta** com regras [Sigma](https://github.com/SigmaHQ/sigma) reais, convertidas para SQL pelo pySigma e executadas no SQLite, mais regras de limite (brute force) que Sigma-para-SQL não consegue expressar.
- **Faz a triagem** de cada alerta com um LLM: severidade, veredito, técnicas MITRE ATT&CK, resumo em linguagem simples e próximos passos, em JSON validado.
- **Funciona com qualquer modelo** via [LiteLLM](https://github.com/BerriAI/litellm): `ollama/...` (local), `anthropic/...`, `openai/...`, `gemini/...` e mais de 100 outros. Trocar de modelo é uma linha no `sentiel.toml`.
- **Enriquece** IPs públicos (GeoIP, AbuseIPDB, VirusTotal) com cache de 24h. Opcional.
- **Notifica** alertas de severidade alta por Telegram e Discord.
- **Conversa** com seus logs: pergunte em linguagem natural e o modelo escreve uma consulta SQL somente leitura.
- **Compara modelos** no conjunto de ataques embutido (`sentiel bench`).

## Arquitetura

Um pipeline linear de funções, sem agentes, filas ou sistema de plugins: a detecção é determinística e o modelo apenas interpreta os alertas, nunca decide quais existem. O diagrama está no [README em inglês](README.md#architecture).

## Início rápido

```bash
git clone https://github.com/shinitihm/Sentiel && cd Sentiel
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install .

sentiel demo --no-ai                  # só detecção, funciona offline
ollama pull llama3.1:8b
sentiel demo -m ollama/llama3.1:8b    # com triagem por IA

cp sentiel.example.toml sentiel.toml  # depois edite: modelo, fontes, notificações
sentiel scan                          # uma passada nos seus logs reais
sentiel watch                         # monitoramento contínuo
sentiel doctor                        # confere config, fontes, modelo e notificações
sentiel alerts / show 3 / report / chat "quais IPs mais erraram login?"
sentiel bench ollama/llama3.1:8b,anthropic/claude-sonnet-5-5
```

Ler o log **Security** do Windows exige um terminal de administrador; sem ele o Sentiel avisa e continua com as outras fontes.

## Rodar como serviço

Rode `sentiel doctor` antes de tudo: ele confere config, banco, regras, fontes de log, modelo e notificações antes de você deixar rodando.

- **Linux:** `contrib/sentiel.service` é uma unit do systemd. Os passos de instalação estão no comentário do cabeçalho. Inicie com `sudo systemctl enable --now sentiel` e confira com a config do serviço: `sudo -u sentiel sh -c 'cd /var/lib/sentiel && sentiel doctor -c /etc/sentiel/sentiel.toml'`.
- **Windows:** `contrib/sentiel-task.xml` é uma tarefa do Agendador de Tarefas que inicia no boot como SYSTEM. Registre com `Register-ScheduledTask` em um PowerShell de administrador (veja o comentário do arquivo), inicie agora com `Start-ScheduledTask -TaskName Sentiel` (o gatilho de boot espera um reinício) e confira, ainda como administrador: `cd C:\ProgramData\Sentiel; sentiel doctor -c C:\ProgramData\Sentiel\sentiel.toml`.

As chaves dos provedores de LLM (`ANTHROPIC_API_KEY` etc.) vêm só do ambiente, que um serviço não herda do seu terminal: use `/etc/sentiel/env` no Linux e variáveis de máquina no Windows (veja os comentários dos arquivos).

Cada etapa grava no SQLite antes da próxima, então parar o serviço nunca perde um alerta.

## Segurança por design

Quem ataca controla o conteúdo dos logs, então os logs são uma superfície de ataque contra a própria IA.

- **Prompt injection não esconde alertas.** A severidade efetiva é `max(nível da regra, severidade da IA)`: o modelo pode aumentar, nunca diminuir. Se a IA chamar de "benigno" uma regra `high`, o alerta aparece como **CONTESTED** e continua sendo notificado. O demo inclui uma linha de comando PowerShell que manda o modelo marcá-la como benigna, e um teste garante que ela continua visível.
- **Logs são dados, não instruções.** Os eventos entram no prompt como JSON dentro de um bloco `<untrusted_log_data>` que o conteúdo do log não consegue fechar, com valores de tamanho limitado. O modelo da triagem não tem ferramentas: só devolve JSON.
- **O chat é somente leitura em três camadas:** o arquivo SQLite abre com `mode=ro`, um *authorizer* do SQLite nega tudo menos `SELECT` em `logs`/`alerts` (então `PRAGMA`, `ATTACH`, escritas e a tabela `state` ficam bloqueados mesmo que o modelo peça) e as consultas têm limite de tempo e de linhas.
- **Privacidade:** usar um modelo não local mostra um aviso único de que detalhes dos alertas saem da máquina. As notificações levam só título, severidade, host e resumo, nunca linhas brutas de log. Segredos ficam no `sentiel.toml` (ignorado pelo git) ou em variáveis de ambiente, e erros de notificação nunca exibem o token do Telegram.
- **Nenhum alerta se perde:** cada etapa grava no SQLite antes da próxima. Se o modelo estiver fora do ar, os alertas ficam *pendentes* e `sentiel triage` tenta de novo depois.

## Limitações

- O `pySigma-backend-sqlite` não suporta busca de texto livre nem agregações. Por isso muitas regras Sigma de Linux não se aplicam, e o brute force é implementado como regras de limite explícitas.
- O conjunto de regras é pequeno e curado (6 regras Sigma + 2 de limite): suficiente para demonstrar o pipeline, não substitui um conjunto de detecção completo.
- A qualidade da triagem depende do modelo; modelos locais pequenos podem precisar da segunda tentativa de JSON. É exatamente o que o `bench` mede.
- A coleta do Windows só funciona no Windows; o demo roda em qualquer sistema.

## Desenvolvimento

```bash
pip install -e ".[dev]"
pytest            # sem rede nem chave de API; o LLM é simulado
ruff check .
SENTIEL_TEST_MODEL=ollama/mistral:latest pytest -m llm   # teste opcional com modelo real
python scripts/generate_demo.py   # regenera o dataset de demo determinístico
```

Licença MIT.
