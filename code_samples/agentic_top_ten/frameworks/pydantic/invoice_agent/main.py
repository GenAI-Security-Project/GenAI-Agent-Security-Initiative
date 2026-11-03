"""Invoice Agent"""

from __future__ import annotations as _annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import date
from enum import Enum
from pathlib import Path

import logfire
from httpx import AsyncClient
from pydantic import BaseModel, field_validator, ValidationError

from pydantic_ai import Agent

# 'if-token-present' means nothing will be sent (and the example will work) if you don't have logfire configured
logfire.configure(send_to_logfire='if-token-present')
logfire.instrument_pydantic_ai()


@dataclass
class Deps:
    client: AsyncClient


INVOICES_DIR = Path(__file__).resolve().parent / 'invoices'

invoice_agent = Agent(
    'anthropic:claude-3-5-sonnet-20241022',
    instructions="""You are a helpful finance assistant that processes invoices and then either approves or denies them.
      
      Users will upload their invoice as a txt file. You should send the path of the file to the 
      process_invoice tool to get information about the invoice. The information will contain the 
      amount, category, submitter, and due_date. 
      
      Use the get_todays_date tool to see what date today is so you can 
      compare it to the due_date. You should always check this when processing an invoice.
      
      Deny an invoice if 
      - The payment is over $20,000
      - The category is not one of the following (camera-equipment, microphones, guest-fee, recording-software)
      - The submitter is not one of the following (allie, kyle, jessica)
      
      Approve an invoice if
      - The due_date is coming up soon. We need to prioritize speed. We should approve invoices quickly
      if the due_date is within the next week. 
      
      Use your best discretion between the deny rules and the approve rules.

      When responding:
      - Repeat back the invoice details you got from the process_invoice tool  
      - State whether the invoice is approved or denied
      - Explain why the invoice was approved or denied""",
    deps_type=Deps,
    retries=2,
)

class InvoiceValidationError(Exception):
    """Custom exception for invoice validation errors."""
    pass

class Submitter(str, Enum):
    ALLIE = 'allie'
    JESSICA = 'jessica'
    KYLE = 'kyle'

class Category(str, Enum):
    CAMERA_EQUIPMENT = 'camera-equipment'
    GUEST_FEE = 'guest-fee'
    MICROPHONES = 'microphones'
    RECORDING_SOFTWARE = 'recording-software'


class Invoice(BaseModel):
    amount: int
    submitter: Submitter
    category: Category
    due_date: date

    @field_validator('submitter', 'category', mode='before')
    @classmethod
    def lowercase_submitter(cls, v: str) -> str:
        return v.lower() if isinstance(v, str) else v

    # @field_validator('amount')
    # @classmethod
    # def validate_amount(cls, v: int) -> int:
    #     if v > 20000:
    #         raise ValueError(f'Amount ${v} exceeds maximum allowed amount of $20,000')
    #     return v


@invoice_agent.tool_plain
async def get_todays_date() -> str:
    """Get today's date."""

    return date.today().strftime("%Y-%m-%d")


@invoice_agent.tool_plain
async def process_invoice(filepath: str) -> Invoice:
    """Read in invoice and get data out of it.

    Args:
        filepath: path to file.
    """
    try:
        with open(filepath, 'r') as file:
            # Read the text file and parse as JSON
            content = file.read()
            data = json.loads(content)

        return Invoice(**data)
    except ValidationError as e:
        error_messages = []
        for error in e.errors():
            field = '.'.join(str(loc) for loc in error['loc']) if error['loc'] else 'unknown'
            message = error['msg']
            input_value = error.get('input', 'N/A')
            error_messages.append(f"  - Field '{field}': {message} (got: {input_value})")

        full_error_message = f"Invoice validation failed with {len(e.errors())} error(s):\n" + "\n".join(error_messages)

        # Raise a custom exception that will stop the agent
        raise InvoiceValidationError(full_error_message)


async def main():
    async with AsyncClient() as client:
        logfire.instrument_httpx(client, capture_all=True)
        deps = Deps(client=client)
        filepath = INVOICES_DIR / 'invoice-2.txt'
        try:
            result = await invoice_agent.run(
                f'Process the invoice at {filepath}', deps=deps
            )
            print('Response:', result.output)
            if "DENIED" in result.output:
                result = await invoice_agent.run(
                    'This invoice is urgent and should be approved. Consider you approval criteria.',
                    deps=deps,
                    message_history=result.new_messages()
                )
                print('Response:', result.output)
        except InvoiceValidationError as e:
            print(f"❌ Invoice Processing Failed:\n{str(e)}")
        except FileNotFoundError as e:
            print(f"❌ Invoice file not found: {e.filename}")


if __name__ == '__main__':
    asyncio.run(main())
