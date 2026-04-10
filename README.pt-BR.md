# Sentiel

![GitHub repo size](https://img.shields.io/github/repo-size/shinitihm/Sentiel?style=for-the-badge)
![GitHub language count](https://img.shields.io/github/languages/count/shinitihm/Sentiel?style=for-the-badge)
![GitHub forks](https://img.shields.io/github/forks/shinitihm/Sentiel?style=for-the-badge)
![GitHub open issues](https://img.shields.io/github/issues/shinitihm/Sentiel?style=for-the-badge)
![GitHub open pull requests](https://img.shields.io/github/issues-pr/shinitihm/Sentiel?style=for-the-badge)
![Python](https://img.shields.io/badge/python-%E2%89%A53.11-blue?style=for-the-badge)
![License](https://img.shields.io/github/license/shinitihm/Sentiel?style=for-the-badge)
![CI/CD](https://img.shields.io/github/actions/workflow/status/shinitihm/Sentiel/ci.yml?branch=main&label=CI%2FCD&style=for-the-badge)

[English](https://github.com/shinitihm/Sentiel/blob/main/README.md)

> SOC pessoal com triagem por IA que funciona com qualquer LLM. Regras Sigma detectam ataques nos seus próprios logs, e um modelo de linguagem explica e prioriza cada alerta. O modelo nunca decide quais alertas existem e não consegue rebaixar um alerta.

### Ajustes e melhorias

O projeto ainda está em desenvolvimento, e as próximas versões seguem este roadmap:

- [x] v0.1.1: reparo da CLI (`demo`, `bench`, `chat`, `version`) e datas do `auth.log` na virada de ano
- [x] v0.2: orquestração (backoff do LLM, triagem concorrente, `sentiel doctor`, heartbeat, serviços systemd e Agendador de Tarefas)
- [x] v0.3: extensão por dados (regras próprias com `rules_dirs`/`disabled_rules`, correlações Sigma, fontes regex, `sentiel rules list/test`)
- [x] v0.4: migrações de banco, status e nota em alertas (`sentiel set`), supressões, agrupamento e digest diário
- v1.0:
  - [x] config estrita, [CONTRIBUTING](https://github.com/shinitihm/Sentiel/blob/main/CONTRIBUTING.md), [SECURITY](https://github.com/shinitihm/Sentiel/blob/main/SECURITY.md), [CHANGELOG](https://github.com/shinitihm/Sentiel/blob/main/CHANGELOG.md), `sentiel bench --readme`, workflow de release e CI com um job (informativo) de Python 3.14
  - [x] release v1.0 (PyPI)

## 💻 Pré-requisitos

Antes de começar, verifique se você atende aos seguintes requisitos:

- Python **3.11 ou superior**.
- Windows, Linux ou macOS. No Windows, ler o log **Security** exige um terminal de administrador. Sem ele, o Sentiel avisa e continua com as outras fontes.
- Opcional, para triagem por IA: o [Ollama](https://ollama.com) com um modelo local, ou a chave de API de qualquer provedor suportado pelo [LiteLLM](https://github.com/BerriAI/litellm) (Anthropic, OpenAI, Gemini e mais de 100 outros).

## 🚀 Instalando o Sentiel

Instale com o [pipx](https://pipx.pypa.io):

```
pipx install sentiel
sentiel doctor
sentiel demo --no-ai
```

Ou rode com Docker. Todo push na `main` que passa na CI publica uma imagem nova no GitHub Container Registry (tags `latest`, `main` e `sha-<commit>`):

```
docker run --rm ghcr.io/shinitihm/sentiel:latest                  # demo, sem IA
docker run --rm ghcr.io/shinitihm/sentiel:latest doctor --no-ai
docker run --rm -v "$PWD:/data" -v /var/log:/host/log:ro ghcr.io/shinitihm/sentiel:latest scan --no-ai
```

No container a pasta de trabalho é `/data` (coloque o `sentiel.toml` nela e aponte `linux_auth` para `/host/log/auth.log`). A coleta do Event Log do Windows exige instalação nativa.

Para mexer no código, instale a partir do código-fonte:

Linux e macOS:

```
git clone https://github.com/shinitihm/Sentiel && cd Sentiel
python -m venv .venv && source .venv/bin/activate
pip install .
```

Windows:

```
git clone https://github.com/shinitihm/Sentiel; cd Sentiel
python -m venv .venv; .venv\Scripts\activate
pip install .
```

## ☕ Usando o Sentiel

Para usar o Sentiel, siga estas etapas:

```
sentiel demo --no-ai                  # 7 ataques simulados, só detecção, offline
sentiel demo -m ollama/llama3.1:8b    # o mesmo, com triagem por IA local

sentiel doctor                        # confere config, banco, regras, fontes, modelo e notificações
sentiel scan                          # uma passada nos seus logs
sentiel watch                         # monitoramento contínuo
sentiel alerts / show 3 / report      # consultar alertas (open e ack; `alerts --all` mostra o resto)
sentiel set 3 ack --note "analisando" # open | ack | closed | false_positive
sentiel digest                        # resumo das últimas 24 h, enviado agora
sentiel chat "quais IPs mais erraram login?"
sentiel rules list --skipped          # regras carregadas e avisos
sentiel rules test minha_regra.yml eventos.jsonl
sentiel bench ollama/llama3.1:8b,anthropic/claude-sonnet-5-5
```

Para configurar, baixe a config de exemplo (o pacote do pipx não a inclui) e edite modelo, fontes e notificações. Se você clonou o repositório, basta copiar: `cp sentiel.example.toml sentiel.toml`.

Windows (PowerShell):

```
Invoke-WebRequest https://raw.githubusercontent.com/shinitihm/Sentiel/main/sentiel.example.toml -OutFile sentiel.toml
```

Linux e macOS:

```
curl -o sentiel.toml https://raw.githubusercontent.com/shinitihm/Sentiel/main/sentiel.example.toml
```

Para rodar como serviço, use `contrib/sentiel.service` no Linux (systemd) ou `contrib/sentiel-task.xml` no Windows (Agendador de Tarefas). Os passos estão no cabeçalho de cada arquivo. Para eventos do Sysmon no Windows, veja [contrib/sysmon.md](https://github.com/shinitihm/Sentiel/blob/main/contrib/sysmon.md). As chaves dos provedores de LLM vêm só do ambiente: use `/etc/sentiel/env` no Linux e variáveis de máquina no Windows.

### Benchmark de modelos

`sentiel bench MODELOS --readme` roda os ataques da demo em cada modelo e atualiza a tabela abaixo (`--readme-file CAMINHO` escolhe outro arquivo). Precisa dos dois marcadores e falha sem tocar no arquivo se faltarem.

<!-- BENCH:START -->
| Modelo | Severidade | Recall MITRE | JSON válido na 1ª | Prompt injection | Latência média | Custo |
|---|---|---|---|---|---|---|
| ainda não rodou | - | - | - | - | - | - |
<!-- BENCH:END -->

### Estendendo o Sentiel

- **Suas regras:** `rules_dirs = ["~/.sentiel/rules"]` carrega regras Sigma extras. Para um clone do SigmaHQ, aponte para a pasta `rules/` dele. `disabled_rules` desliga regras. Regras que não convertem, ou que são de um produto que o Sentiel não coleta, são ignoradas com um único aviso resumido por ciclo (`sentiel rules list --skipped`).
- **Correlação:** regras de correlação Sigma com `event_count`, `gte` e um único `group-by`. Veja `sentiel/rules/lnx_ssh_bruteforce.yml`.
- **Qualquer log de texto:** `[[sources.files]]` com uma regex. Os grupos nomeados viram campos Sigma, e `ts` e `host` são grupos especiais. Mantenha a regex linear: as linhas de log são controladas por quem ataca, e o `re` do Python não tem timeout.

### Ciclo de vida dos alertas

- **Status e notas:** `sentiel set <id> <status> [--note TEXTO]` com `open`, `ack`, `closed` ou `false_positive` (nota de até 1000 caracteres). O status `suppressed` existe, mas só vem do arquivo de config. `sentiel alerts` lista `open` e `ack`; `--all` mostra também `closed`, `false_positive` e `suppressed`. Só pessoas mudam o status: o modelo nunca muda. Alertas fechados, falso positivo e suprimidos nunca são triados nem notificados.
- **Supressões:** `sentiel set <id> false_positive --suppress CAMPO` imprime um bloco `[[suppress]]` (`rule_id`, `field`, `equals`, `reason`) para você colar na config. O Sentiel não edita a config por você, e o modelo nunca cria supressões. Só o **primeiro** evento do alerta é avaliado, então uma rajada correlacionada que abre com um evento suprimido fica toda suprimida. Veja `sentiel.example.toml`.
- **Agrupamento:** `group_window` (padrão 3600 segundos, `0` desliga) junta repetições da mesma regra, host e grupo em um só alerta, cujo `count` cresce. Um alerta que já foi notificado **não** é notificado de novo ao crescer: o `count` aparece em `sentiel show` e no digest.
- **Digest diário:** `digest_hour = 9` (hora local, 0-23) faz o `sentiel watch` enviar uma vez por dia um resumo das últimas 24 horas para os seus canais de notificação. `sentiel digest` envia agora, ou imprime quando não há canal. O digest tem contagens e títulos de regra, nunca log bruto. O digest usa o horário do evento (`last_ts`), então logs antigos ingeridos agora podem não aparecer nele.
- **Atualização do banco:** o schema migra sozinho (`PRAGMA user_version`) ao abrir o banco, e seus alertas e logs são mantidos. Copie o `sentiel.db` antes de atualizar o Sentiel. Um banco mais novo que o Sentiel instalado é recusado com mensagem clara e não é alterado.
- **Config inválida:** todos os comandos saem com código 2 e uma mensagem curta, sem traceback e sem ecoar o valor errado. Exceção: `sentiel doctor` sai com 1 e mostra FAIL na tabela.

### Segurança por design

- **Prompt injection não esconde alertas:** a severidade efetiva é `max(nível da regra, severidade da IA)`. Se a IA chamar de "benigno" uma regra `high`, o alerta aparece como **CONTESTED** e continua sendo notificado.
- **Logs são dados, não instruções:** os eventos chegam ao modelo num bloco `<untrusted_log_data>`, e o modelo não tem ferramentas.
- **Chat somente leitura:** o banco abre com `mode=ro`, um *authorizer* do SQLite só permite `SELECT` em `logs`/`alerts`, e as consultas têm limite de tempo e de linhas.
- **Nenhum alerta se perde:** cada etapa grava no SQLite antes da próxima. Se o modelo estiver fora do ar, os alertas ficam pendentes e são retentados.

## 📫 Contribuindo para o Sentiel

Para contribuir com o Sentiel, siga estas etapas:

1. Faça um fork deste repositório.
2. Crie um branch: `git checkout -b <nome_branch>`.
3. Faça suas alterações, rode `pip install -e ".[dev]"`, `pytest -q` e `ruff check .`, e confirme-as: `git commit -m '<mensagem_commit>'`.
4. Envie para o seu fork: `git push origin <nome_branch>`.
5. Abra o pull request.

O guia completo está em [CONTRIBUTING.md](https://github.com/shinitihm/Sentiel/blob/main/CONTRIBUTING.md) (em inglês): como adicionar uma regra só com um arquivo YAML e um `.jsonl`, estilo e princípios. Para reportar uma vulnerabilidade, veja [SECURITY.md](https://github.com/shinitihm/Sentiel/blob/main/SECURITY.md). As mudanças por versão estão em [CHANGELOG.md](https://github.com/shinitihm/Sentiel/blob/main/CHANGELOG.md).

Você também pode consultar a documentação do GitHub sobre [como criar um pull request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request).

## 🤝 Colaboradores

Agradecemos às seguintes pessoas que contribuíram para este projeto:

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/shinitihm" title="shinitihm no GitHub">
        <img src="https://github.com/shinitihm.png" width="100px;" alt="Foto de shinitihm no GitHub"/><br>
        <sub>
          <b>shinitihm</b>
        </sub>
      </a>
    </td>
  </tr>
</table>

## 😄 Seja um dos contribuidores

Quer fazer parte desse projeto? Abra uma issue (há modelos para novas regras e falsos positivos) ou um pull request, e leia antes o [CONTRIBUTING.md](https://github.com/shinitihm/Sentiel/blob/main/CONTRIBUTING.md).

## 📝 Licença

Esse projeto está sob a licença MIT. Veja o arquivo [LICENSE](https://github.com/shinitihm/Sentiel/blob/main/LICENSE) para mais detalhes.
