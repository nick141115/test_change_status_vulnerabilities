import random
from datetime import datetime, timedelta

import allure
import pytest
from playwright.sync_api import expect

from src.api.policies.policies_models import (
    ChangeVulnerabilityStatusToAwaitingFixActionResultModel,
    CreationModelModel,
    PolicyType,
)
from src.constants.assets_pdql_constants import AssetsPdql
from src.constants.vulnerability_card_constants import VulnerabilityCardConstants
from src.pages.siem.vulnerability_card.vulnerability_card_page import VulnerabilityCardPage
from src.tools.helper_random import helper_random

pdql_status_new = AssetsPdql.VULNERABILITIES_WITH_ID_AND_PARTICULAR_STATUSES.format("New")
status_in_progress = "В работе"
url_params_pdql_status_new = {"pdqlQuery": pdql_status_new, "viewMode": "vulnerability"}


@allure.label("team", "VM Core")
@allure.label("product", "Управление уязвимостями")
@allure.label("component", "Статусы уязвимости")
@allure.label("layer", "UI Tests")
@pytest.mark.vm
@pytest.mark.ui
@pytest.mark.regress
class TestSetStatus:
    """Смена статусов экземпляров уязвимостей."""

    @allure.id("258401")
    @allure.title("Изменение статуса в карточке уязвимости 'Новая' → 'В работе'")
    def test_changing_vulnerability_status_new_in_progress(self, vulner_card_ids, page):

        with allure.step("Открываем карточку уязвимости"):
            vulner_card = VulnerabilityCardPage(page)
            vulner_card.open_page(
                params={
                    "vulnerabilityInstanceId": vulner_card_ids.id,
                    "vulnerabilityId": vulner_card_ids.internalId,
                }
            )
            vulner_card.wait_for_page_update()

        with allure.step("Проверяем, что открылась карточка уязвимости"):
            expect(vulner_card.card_header).to_be_visible()
            vulner_card.check_page_url()

        with allure.step("Изменяем статус уязвимости"):
            expect(vulner_card.button_change_status).to_be_visible()
            vulner_card.button_change_status.click()
            vulner_card.get_button_by_text(status_in_progress).click()

        with allure.step(f'Проверяем, что статус уязвимости изменился на "{status_in_progress}"'):
            vulner_card.wait_for_page_update()
            expect(vulner_card.left_section.vulnerability_status).to_have_text(status_in_progress)

    @allure.id("258422")
    @pytest.mark.smoke
    @allure.title("Изменение статуса в карточке уязвимости 'Новая' → 'Исправляется'")
    def test_changing_vulnerability_status_in_progress_to_awaiting_fix(self, vulner_card_ids, page):
        text_comment = helper_random.random_string
        status_awaiting_fix = "Исправляется"
        time_status_awaiting_fix = "23:59"

        with allure.step("Открываем карточку уязвимости"):
            vulner_card = VulnerabilityCardPage(page)
            vulner_card.open_page(
                params={
                    "vulnerabilityInstanceId": vulner_card_ids.id,
                    "vulnerabilityId": vulner_card_ids.internalId,
                }
            )
            vulner_card.wait_for_page_update()

        with allure.step("Проверяем, что открылась карточка уязвимости"):
            expect(vulner_card.card_header).to_be_visible()
            vulner_card.check_page_url()

        with allure.step("Изменяем статус уязвимости"):
            expect(vulner_card.button_change_status).to_be_visible()
            vulner_card.button_change_status.click()
            vulner_card.get_button_by_text(status_awaiting_fix).click()

        with allure.step("Вводим дату"):
            expect(vulner_card.vulner_change_state_modal.date).to_be_visible()
            vulner_card.vulner_change_state_modal.date.click()

            today = datetime.today()
            tomorrow = today + timedelta(days=1)
            formatted_tomorrow = tomorrow.strftime("%d.%m.%Y")
            vulner_card.vulner_change_state_modal.date.fill(formatted_tomorrow)

        with allure.step("Выбираем часовой пояс"):
            expect(vulner_card.vulner_change_state_modal.time_zones).to_be_visible()
            vulner_card.vulner_change_state_modal.time_zones.click()
            random_nth = random.randint(0, 33)
            time_zone = vulner_card.vulner_change_state_modal.get_time_zones_dropdown_item(random_nth)
            expect(time_zone).to_be_visible()
            time_zone.click()

        with allure.step("Вводим время"):
            expect(vulner_card.vulner_change_state_modal.time).to_be_visible()
            vulner_card.vulner_change_state_modal.time.click()
            vulner_card.vulner_change_state_modal.time.fill(time_status_awaiting_fix)

        with allure.step("Вводим комментарий"):
            expect(vulner_card.vulner_change_state_modal.comment).to_be_visible()
            vulner_card.vulner_change_state_modal.comment.click()
            vulner_card.vulner_change_state_modal.comment.fill(text_comment)

        with allure.step("Нажимаем кнопку 'Изменить'"):
            expect(vulner_card.vulner_change_state_modal.edit_button).to_be_visible()
            vulner_card.vulner_change_state_modal.edit_button.click()

        with allure.step(f'Проверяем, что статус уязвимости изменился на "{status_awaiting_fix}"'):
            expect(vulner_card.left_section.vulnerability_status).to_have_text(status_awaiting_fix)

            latest_status_from_history = vulner_card.left_section.get_status_from_history_by_nth(-2)
            expect(latest_status_from_history).to_be_visible()

            expect(latest_status_from_history).to_have_text("Нужно исправить к")

            latest_time_from_history = vulner_card.left_section.get_status_from_history_by_nth(-1)
            expect(latest_time_from_history).to_be_visible()
            expect(latest_time_from_history).to_have_text(time_status_awaiting_fix)

    @allure.id("258508")
    @allure.title("Изменение статуса в карточке уязвимости 'Новая' → 'Исключена'")
    def test_changing_vulnerability_status_awaiting_fix_to_excluded(self, vulner_card_ids, page):

        clarification_to_status_false_alarm = VulnerabilityCardConstants.CLARIFICATION_TO_STATUS_FALSE_ALARM

        with allure.step("Открываем карточку уязвимости"):
            vulner_card = VulnerabilityCardPage(page)
            vulner_card.open_page(
                params={
                    "vulnerabilityInstanceId": vulner_card_ids.id,
                    "vulnerabilityId": vulner_card_ids.internalId,
                }
            )
            vulner_card.wait_for_page_update()

        with allure.step("Проверяем, что открылась карточка уязвимости"):
            expect(vulner_card.card_header).to_be_visible()
            vulner_card.check_page_url()

        with allure.step("Изменяем статус уязвимости"):
            expect(vulner_card.button_change_status).to_be_visible()
            vulner_card.button_change_status.click()
            vulner_card.get_button_by_text(VulnerabilityCardConstants.STATUS_EXCLUDED).click()

        with allure.step("Выбираем уточнение к статусу"):
            expect(vulner_card.vulner_change_state_modal.clarification_to_status_window_awaiting_fix).to_be_visible()
            vulner_card.vulner_change_state_modal.clarification_to_status_window_awaiting_fix.click()
            vulner_change_state_modal = (
                vulner_card.vulner_change_state_modal.get_variant_clarification_to_status_by_text
            )
            expect(
                vulner_change_state_modal(VulnerabilityCardConstants.CLARIFICATION_TO_STATUS_COMPENSATORY_MEASURES)
            ).to_be_visible()
            vulner_change_state_modal(VulnerabilityCardConstants.CLARIFICATION_TO_STATUS_COMPENSATORY_MEASURES).click()

        with allure.step("Нажимаем кнопку 'Изменить'"):
            expect(vulner_card.vulner_change_state_modal.edit_button).to_be_visible()
            vulner_card.vulner_change_state_modal.edit_button.click()

        with allure.step(
            f'Проверяем, что статус уязвимости изменился на "{VulnerabilityCardConstants.STATUS_EXCLUDED}"'
        ):
            vulner_card.wait_for_page_update()
            expect(vulner_card.left_section.vulnerability_status).to_have_text(
                VulnerabilityCardConstants.STATUS_EXCLUDED
            )

            last_status_from_history = vulner_card.left_section.get_status_from_history_by_nth(-4)
            expect(last_status_from_history).to_be_visible()
            expect(last_status_from_history).to_contain_text(
                VulnerabilityCardConstants.CLARIFICATION_TO_STATUS_COMPENSATORY_MEASURES
            )

        with allure.step("Открываем модальное окно изменения уточнения статуса уязвимости"):
            expect(vulner_card.button_change_status).to_be_visible()
            vulner_card.button_change_status.click()
            vulner_card.get_button_by_text("Изменить уточнение и дату").click()

        with allure.step("Выбираем уточнение к статусу"):
            expect(vulner_card.vulner_change_state_modal.clarification_to_status_window_excluded).to_be_visible()
            vulner_card.vulner_change_state_modal.clarification_to_status_window_excluded.click()

            vulner_change_state_modal = (
                vulner_card.vulner_change_state_modal.get_variant_clarification_to_status_by_text
            )
            expect(vulner_change_state_modal(clarification_to_status_false_alarm)).to_be_visible()
            vulner_change_state_modal(clarification_to_status_false_alarm).click()

        with allure.step("Меняем дату"):
            expect(vulner_card.vulner_change_state_modal.link_thirty_days).to_be_visible()
            vulner_card.vulner_change_state_modal.link_thirty_days.click()

        with allure.step("Нажимаем кнопку 'Изменить'"):
            expect(vulner_card.vulner_change_state_modal.edit_button).to_be_visible()
            vulner_card.vulner_change_state_modal.edit_button.click()

        with allure.step("Проверяем, что статус уязвимости не изменился"):
            vulner_card.wait_for_page_update()
            expect(vulner_card.left_section.link_vulnerability_statuses_history).to_be_visible()
            vulner_card.left_section.link_vulnerability_statuses_history.click()
            vulner_card.wait_for_page_update()
            expect(vulner_card.left_section.vulnerability_status).to_have_text(
                VulnerabilityCardConstants.STATUS_EXCLUDED
            )

        with allure.step(f"Проверяем, что уточнение изменилось на {clarification_to_status_false_alarm}"):
            last_status_from_history = vulner_card.left_section.get_status_from_history_by_nth(-4)
            expect(last_status_from_history).to_be_visible()
            expect(last_status_from_history).to_contain_text(clarification_to_status_false_alarm)

    @allure.id("554542")
    @allure.title("Изменение статуса уязвимости 'Новая' → 'В работе' (в правом сайдбаре)")
    @pytest.mark.parametrize("open_and_wait_assets_page", [url_params_pdql_status_new], indirect=True)
    def test_changing_vulnerability_status_new_in_progress_sidebar(self, assets_page, open_and_wait_assets_page):
        vulnerability_status = "Статус уязвимости"
        change_status = "Изменить статус"

        with allure.step("Открываем карточку уязвимости в правом сайдбаре"):
            assets_page.wait_for_page_update()
            random_row = assets_page.grid.get_random_row()
            vulner_id = assets_page.grid.get_row_cell_by_column_name(
                random_row, "Идентификатор экземпляра уязвимости"
            ).inner_text()
            random_row.click()
            assets_page.wait_for_page_update()

        with allure.step("Изменяем статус уязвимости"):
            expect(assets_page.right_sidebar.vulnerability.root, "Не открылась карточка уязвимости").to_be_visible()
            assets_page.right_sidebar.get_button_by_text(change_status).click()
            assets_page.right_sidebar.get_button_by_text(status_in_progress).click()
            assets_page.wait_for_page_update()

        with allure.step(f'Проверяем, что статус уязвимости изменился на "{status_in_progress}"'):
            assets_page.pdql.do_pdql_with_keyboard_button(AssetsPdql.VULNERS_FILTER_BY_ID.format(vulner_id))
            assets_page.wait_for_page_update()
            first_row_from_grid = assets_page.grid.get_row_by_index(0)
            expect(
                assets_page.grid.get_row_cell_by_column_name(first_row_from_grid, vulnerability_status)
            ).to_be_visible()
            expect(
                assets_page.grid.get_row_cell_by_column_name(first_row_from_grid, vulnerability_status)
            ).to_have_text(status_in_progress)
            expect(assets_page.grid.get_row_cell_by_column_name(first_row_from_grid, "Устранение")).to_have_text(
                "Вручную"
            )
