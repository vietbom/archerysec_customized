from django import template

from utility.references import reference_items

register = template.Library()
register.filter("reference_items", reference_items)
