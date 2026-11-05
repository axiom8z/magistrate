# How to label a tool

You're deciding how much the gateway should trust each tool. Work only from the schema file you were given: each tool's name, description and parameters. Don't read AgentDojo's task files or logs, this repo's forecasts, or anyone else's labels. The labels have to come from the tools and not from the tests.

When you're unsure, say so. "Unsure" always lands on the strict side, so it never lets anything through. Every question below takes `yes`, `no` or `unsure`.

The user is the person using the agent. The operator is whoever runs this deployment and sets up the gateway. Everyone else is an outsider, and that includes the businesses and services behind a tool.

## The questions

Answer these for every tool. If an acting tool's schema doesn't say what it returns, answer questions 1 and 5 from what it most likely returns, or say `unsure`.

1. **`outsiders_write_output`: could anyone but the user or the operator write what this tool returns, even by getting the agent to do it?** If other people can send email, post messages or edit a shared page, then their words can come back through this tool. A number other people can move counts too. A value only the user or the operator can set is a `no`.

2. **`changes_or_reaches`: can this tool change anything, or can any argument reach anyone but the tool's own service?** If either is true, the tool acts, whatever its name says. A tool called `get_` that fetches a URL you give it is sending that URL to someone. A read that changes nothing and sends nothing elsewhere is a `no`, even if an argument chooses whose data it opens. If you say `unsure`, answer questions 3 and 4 as if you'd said `yes`.

3. **`args`: what does each argument do?** Give each one a role from the list below. If you're unsure, use `control`. You only need to answer this for tools that act.

4. **`undoable`: can the action be undone?** Say `no` or `unsure` if it can't be undone or you aren't sure, which count the same. Money that has been sent, a message someone has read, and a deleted file with no bin all count as `no`. For a tool that doesn't act, write `yes`.

5. **`sensitive`: is returning credentials, government IDs, card numbers or bank account numbers part of what this tool is for?** A profile with a passport number is a `yes`. Free text that could happen to hold one, like an email or a document, is a `no`, because the secret scanner covers known formats there.

You can also give a **`store`**: a short name for the data a tool writes, like `calendar`. Give the same name to every tool that writes the same data, and to a tool that reads it. If a tool touches two kinds of data, name the one it writes. If a tool's output is written by another tool in the list, that matters for question 1.

## Roles for arguments

| Role | Use it when | What the gateway does |
|---|---|---|
| `control` | It chooses who, what or where: a recipient, a file, a URL, an account | The value must trace to the user's prompt or another trusted source, or a person is asked |
| `content` | It's free text the user wants written: a message body, a note | Allowed, but any link or address inside it has to trace to a source |
| `quantity` | It's how much of something: money, units | Allowed from 0 up to a ceiling, or if the prompt names the number |
| `number`, `boolean`, `date` | It's that type and only that type, and it can't choose a target. `date` covers dates and times | Must match the type, or it's treated as `control` |
| `enum:a,b` | It can only be one of a short fixed list | Must be on the list, or it's treated as `control` |
| `credential` | It's a password, a token or a key | It must appear in the user's prompt |

If an argument could do two of these jobs, pick the stricter one. An ID that selects a record is `control`, even though it looks like plain data.

## What to hand back

One JSON file with every tool from the schema file:

```json
{"labeller": "your name",
 "tools": {
  "crm_find_notes": {"outsiders_write_output": "yes", "changes_or_reaches": "no", "undoable": "yes", "sensitive": "no", "store": "crm"},
  "crm_edit_note": {"outsiders_write_output": "yes", "changes_or_reaches": "yes", "undoable": "yes", "sensitive": "no", "store": "crm",
                    "args": {"note_id": "control", "text": "content"}},
  "pay_transfer": {"outsiders_write_output": "yes", "changes_or_reaches": "yes", "undoable": "no", "sensitive": "no",
                   "args": {"to": "control", "amount": "quantity", "memo": "content", "on": "date"}}
 }}
```

Those three tools are made up, and aren't in the benchmark.

## What happens next

`bench/label/labels.py merge` combines two labellers' files. For every question the stricter answer wins, and every disagreement is counted and published. Anyone who labels after seeing these numbers is credited as such, and what they knew is written down.
